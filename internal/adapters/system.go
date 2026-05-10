package adapters

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

const commandTimeout = 30 * time.Second

// defaultAllowlist is the built-in set of safe commands.
var defaultAllowlist = map[string]bool{
	// System information
	"uptime": true, "whoami": true, "hostname": true, "date": true,
	"uname": true, "id": true, "w": true, "arch": true,

	// Resource monitoring
	"df": true, "free": true, "ps": true, "top": true, "vmstat": true,
	"lscpu": true, "lsblk": true, "iostat": true, "sar": true,

	// Filesystem (read-only)
	"ls": true, "cat": true, "pwd": true, "file": true,
	"head": true, "tail": true, "wc": true, "find": true,
	"du": true, "stat": true, "tree": true, "grep": true,

	// Environment
	"env": true, "printenv": true, "echo": true,

	// Network diagnostics
	"ip": true, "ifconfig": true, "netstat": true, "ss": true,
	"dig": true, "nslookup": true, "ping": true, "traceroute": true,
	"curl": true, "wget": true, "which": true, "nc": true,

	// DevOps / AI agent tools
	"git": true, "docker": true, "kubectl": true, "systemctl": true,
	"make": true, "go": true, "npm": true, "node": true,
	"python": true, "python3": true, "pip": true, "pip3": true,
	"cargo": true, "rustc": true, "terraform": true, "helm": true,
}

// SystemAdapter executes OS commands via os/exec.
// In "allowlist" mode (default), only commands on the allowlist are permitted.
// In "passthrough" mode, all commands are allowed — rely on the firewall for safety.
type SystemAdapter struct {
	mode      string
	allowlist map[string]bool
}

// NewSystemAdapter creates a SystemAdapter. Mode is "allowlist" or "passthrough".
// extraCommands is a comma-separated list of commands to add to the allowlist.
func NewSystemAdapter(mode, extraCommands string) *SystemAdapter {
	a := &SystemAdapter{
		mode:      mode,
		allowlist: make(map[string]bool, len(defaultAllowlist)),
	}

	for cmd := range defaultAllowlist {
		a.allowlist[cmd] = true
	}

	if extraCommands != "" {
		for _, cmd := range strings.Split(extraCommands, ",") {
			cmd = strings.TrimSpace(cmd)
			if cmd != "" {
				a.allowlist[cmd] = true
			}
		}
	}

	// HIVE_ALLOWLIST_COMMANDS env var overlay for agent-side overrides.
	if envExtra := os.Getenv("HIVE_ALLOWLIST_COMMANDS"); envExtra != "" {
		for _, cmd := range strings.Split(envExtra, ",") {
			cmd = strings.TrimSpace(cmd)
			if cmd != "" {
				a.allowlist[cmd] = true
			}
		}
	}

	return a
}

// Name returns the adapter identifier including its mode.
func (s *SystemAdapter) Name() string {
	return fmt.Sprintf("SystemAdapter (%s mode)", s.mode)
}

// ExecuteIntent processes a command payload.
func (s *SystemAdapter) ExecuteIntent(payload []byte) ([]byte, error) {
	commandStr := strings.TrimSpace(string(payload))
	if commandStr == "" {
		return nil, fmt.Errorf("empty command payload")
	}

	tokens := strings.Fields(commandStr)
	binary := tokens[0]
	args := tokens[1:]

	if s.mode == "allowlist" && !s.allowlist[binary] {
		log.Printf("[ADAPTER] BLOCKED disallowed command: %q", binary)
		return nil, fmt.Errorf("command %q is not in the allowlist — execution denied", binary)
	}

	log.Printf("[ADAPTER] Executing: %s %s", binary, strings.Join(args, " "))

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, args...)
	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		log.Printf("[ADAPTER] Command timed out after %v: %q", commandTimeout, commandStr)
		return nil, fmt.Errorf("command timed out after %v", commandTimeout)
	}

	if err != nil {
		log.Printf("[ADAPTER] Command exited with error: %v (output: %d bytes)", err, len(output))
		return []byte(fmt.Sprintf("command error: %v\n\n%s", err, string(output))), nil
	}

	log.Printf("[ADAPTER] Command completed: %q (%d bytes output)", commandStr, len(output))
	return output, nil
}

// ListAllowedCommands returns the current allowlist for debugging.
func (s *SystemAdapter) ListAllowedCommands() []string {
	cmds := make([]string, 0, len(s.allowlist))
	for cmd := range s.allowlist {
		cmds = append(cmds, cmd)
	}
	return cmds
}

// ListAllowedCommands returns the default allowlist (legacy compatibility).
func ListAllowedCommands() []string {
	cmds := make([]string, 0, len(defaultAllowlist))
	for cmd := range defaultAllowlist {
		cmds = append(cmds, cmd)
	}
	return cmds
}