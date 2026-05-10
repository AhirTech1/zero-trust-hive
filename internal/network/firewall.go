package network

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"
)

// FirewallRule defines a single destructive pattern the firewall checks.
type FirewallRule struct {
	Pattern     *regexp.Regexp
	Category    string
	Description string
	Severity    string
}

// FirewallVerdict is the result of a firewall inspection.
type FirewallVerdict struct {
	Allowed    bool                `json:"allowed"`
	Violations []FirewallViolation `json:"violations,omitempty"`
}

// FirewallViolation describes a single rule that was triggered.
type FirewallViolation struct {
	Category    string `json:"category"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Matched     string `json:"matched"`
}

// SemanticFirewall inspects command payloads for destructive patterns.
// Thread-safe and tracks inspection statistics.
type SemanticFirewall struct {
	mu    sync.RWMutex
	rules []FirewallRule

	totalInspected uint64
	totalBlocked   uint64
}

var defaultRules = []FirewallRule{
	// ── Recursive/Forced Deletions ─────────────────────────────────────
	{
		Pattern:     regexp.MustCompile(`(?i)\brm\s+(-[rRf]+\s+|.*--no-preserve-root)`),
		Category:    "Bash",
		Description: "rm with recursive/force flags",
		Severity:    "critical",
	},
	// ── Database Drops ─────────────────────────────────────────────────
	{
		Pattern:     regexp.MustCompile(`(?i)\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX|VIEW)\b`),
		Category:    "SQL",
		Description: "DROP statement (table/database/schema destruction)",
		Severity:    "critical",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)\bDELETE\s+FROM\b`),
		Category:    "SQL",
		Description: "DELETE FROM statement (record destruction)",
		Severity:    "high",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)\bTRUNCATE\s+(TABLE\s+)?\b`),
		Category:    "SQL",
		Description: "TRUNCATE statement (table wipe)",
		Severity:    "critical",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)\bALTER\s+TABLE\b`),
		Category:    "SQL",
		Description: "ALTER TABLE statement (schema modification)",
		Severity:    "high",
	},
	// ── Filesystem Formatters ──────────────────────────────────────────
	{
		Pattern:     regexp.MustCompile(`(?i)\bmkfs\b`),
		Category:    "Bash",
		Description: "mkfs command (filesystem format)",
		Severity:    "critical",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)\bfdisk\b`),
		Category:    "Bash",
		Description: "fdisk command (partition table manipulation)",
		Severity:    "critical",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)\bdd\s+if=`),
		Category:    "Bash",
		Description: "dd with input file (raw disk write)",
		Severity:    "critical",
	},
	// ── Fork Bombs ─────────────────────────────────────────────────────
	{
		Pattern:     regexp.MustCompile(`:\(\)\s*\{\s*:\|:\s*&\s*\}\s*;:`),
		Category:    "Bash",
		Description: "Fork bomb (resource exhaustion attack)",
		Severity:    "critical",
	},
	// ── Privilege Escalation ───────────────────────────────────────────
	{
		Pattern:     regexp.MustCompile(`(?i)\bGRANT\s+(ALL|SELECT|INSERT|UPDATE|DELETE)\b`),
		Category:    "SQL",
		Description: "GRANT statement (privilege escalation)",
		Severity:    "high",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)\bREVOKE\b`),
		Category:    "SQL",
		Description: "REVOKE statement (privilege manipulation)",
		Severity:    "high",
	},
	// ── Credential Exfiltration ────────────────────────────────────────
	{
		Pattern:     regexp.MustCompile(`(?i)\bPASSWORDS?\b`),
		Category:    "SQL",
		Description: "PASSWORD keyword (credential exfiltration attempt)",
		Severity:    "high",
	},
	// ── Block Device Writes ────────────────────────────────────────────
	{
		Pattern:     regexp.MustCompile(`(?i)>\s*/dev/[sh]da`),
		Category:    "Bash",
		Description: "Direct write to block device (disk destruction)",
		Severity:    "critical",
	},
	// ── System Control ─────────────────────────────────────────────────
	{
		Pattern:     regexp.MustCompile(`(?i)\bshutdown\b|\breboot\b|\binit\s+0\b`),
		Category:    "System",
		Description: "System shutdown/reboot command",
		Severity:    "high",
	},
	{
		Pattern:     regexp.MustCompile(`(?i)\bchmod\s+(-[rR]+\s+)?[0-7]{3,4}\s+/`),
		Category:    "Bash",
		Description: "chmod on root paths (permission manipulation)",
		Severity:    "high",
	},
	// ── Obfuscation: Escaped characters ────────────────────────────────
	{
		Pattern:     regexp.MustCompile(`(?i)r\\\s*m\s+-`),
		Category:    "Bash",
		Description: "escaped rm command (obfuscation attempt)",
		Severity:    "critical",
	},
	// ── Obfuscation: Command substitution wrapping destructive commands ─
	{
		Pattern:     regexp.MustCompile(`(?i)\$\(\s*.*\brm\b.*\s*\)`),
		Category:    "Bash",
		Description: "command substitution wrapping rm (obfuscation)",
		Severity:    "critical",
	},
	{
		Pattern:     regexp.MustCompile("`\\s*.*\\brm\\b.*\\s*`"),
		Category:    "Bash",
		Description: "backtick substitution wrapping rm (obfuscation)",
		Severity:    "critical",
	},
	// ── Obfuscation: curl/wget piped to shell ──────────────────────────
	{
		Pattern:     regexp.MustCompile(`(?i)\b(?:curl|wget)\b.+\|\s*(ba)?sh\b`),
		Category:    "Bash",
		Description: "curl or wget piped to shell (remote code execution)",
		Severity:    "critical",
	},
	// ── Obfuscation: Full path to destructive binaries ──────────────────
	{
		Pattern:     regexp.MustCompile(`(?i)\b/usr/bin/rm\b|\b/bin/rm\b`),
		Category:    "Bash",
		Description: "full path to rm (obfuscation attempt)",
		Severity:    "critical",
	},
	// ── Obfuscation: chmod 777 anywhere ─────────────────────────────────
	{
		Pattern:     regexp.MustCompile(`(?i)\bchmod\s+.*777\b`),
		Category:    "Bash",
		Description: "chmod 777 (world-writable permission)",
		Severity:    "high",
	},
	// ── Obfuscation: Base64 decode piped to execution ───────────────────
	{
		Pattern:     regexp.MustCompile(`(?i)\bbase64\s+.*-d.*\|`),
		Category:    "Bash",
		Description: "base64 decode piped to command (payload obfuscation)",
		Severity:    "critical",
	},
	// ── Obfuscation: eval with quoted input ─────────────────────────────
	{
		Pattern:     regexp.MustCompile(`(?i)\beval\s+['"]`),
		Category:    "Bash",
		Description: "eval with quoted input (dynamic code execution)",
		Severity:    "high",
	},
}

// NewSemanticFirewall creates a firewall with the default ruleset.
func NewSemanticFirewall() *SemanticFirewall {
	fw := &SemanticFirewall{
		rules: make([]FirewallRule, len(defaultRules)),
	}
	copy(fw.rules, defaultRules)

	log.Printf("[FIREWALL] Semantic Firewall initialized — %d rules loaded", len(fw.rules))
	return fw
}

// AddRule appends a custom rule to the firewall at runtime.
func (fw *SemanticFirewall) AddRule(rule FirewallRule) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	fw.rules = append(fw.rules, rule)
}

// Inspect checks a command for destructive patterns. Returns nil if safe,
// or an error describing the first violation found.
func (fw *SemanticFirewall) Inspect(command string) error {
	fw.mu.RLock()
	rules := fw.rules
	fw.mu.RUnlock()

	normalized := strings.TrimSpace(command)
	if normalized == "" {
		return fmt.Errorf("empty command payload")
	}

	fw.mu.Lock()
	fw.totalInspected++
	fw.mu.Unlock()

	for _, rule := range rules {
		match := rule.Pattern.FindString(normalized)
		if match != "" {
			fw.mu.Lock()
			fw.totalBlocked++
			fw.mu.Unlock()

			log.Printf("[FIREWALL] BLOCKED [%s/%s]: %s — matched: %q (inspected: %d, blocked: %d)",
				rule.Category, rule.Severity, rule.Description, match,
				fw.totalInspected, fw.totalBlocked)

			return fmt.Errorf(
				"BLOCKED [%s]: %s — matched: %q",
				rule.Category, rule.Description, match,
			)
		}
	}

	return nil
}

// InspectVerbose returns ALL violations found in the command.
func (fw *SemanticFirewall) InspectVerbose(command string) FirewallVerdict {
	fw.mu.RLock()
	rules := fw.rules
	fw.mu.RUnlock()

	normalized := strings.TrimSpace(command)
	verdict := FirewallVerdict{Allowed: true}

	for _, rule := range rules {
		match := rule.Pattern.FindString(normalized)
		if match != "" {
			verdict.Allowed = false
			verdict.Violations = append(verdict.Violations, FirewallViolation{
				Category:    rule.Category,
				Description: rule.Description,
				Severity:    rule.Severity,
				Matched:     match,
			})
		}
	}

	return verdict
}

// FirewallStats contains inspection statistics.
type FirewallStats struct {
	TotalInspected uint64    `json:"total_inspected"`
	TotalBlocked   uint64    `json:"total_blocked"`
	RuleCount      int       `json:"rule_count"`
	Uptime         string    `json:"uptime"`
	StartedAt      time.Time `json:"started_at"`
}

// Stats returns the current firewall statistics.
func (fw *SemanticFirewall) Stats() FirewallStats {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	return FirewallStats{
		TotalInspected: fw.totalInspected,
		TotalBlocked:   fw.totalBlocked,
		RuleCount:      len(fw.rules),
	}
}

var defaultFirewall = NewSemanticFirewall()

// InspectPayload is a convenience function using the default firewall.
func InspectPayload(command string) error {
	return defaultFirewall.Inspect(command)
}

// InspectPayloadVerbose is a convenience function for verbose inspection.
func InspectPayloadVerbose(command string) FirewallVerdict {
	return defaultFirewall.InspectVerbose(command)
}