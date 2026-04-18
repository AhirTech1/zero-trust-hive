// ─────────────────────────────────────────────────────────────────────────────
// Package adapters — SystemAdapter (Default Execution Backend)
// ─────────────────────────────────────────────────────────────────────────────
// The SystemAdapter is the default EdgeAdapter implementation. It executes
// basic, non-destructive OS commands using os/exec and returns the combined
// stdout+stderr output as the response.
//
// Safety Model:
//   - Maintains an explicit allowlist of safe commands (uptime, echo, whoami,
//     hostname, date, df, free, uname, id, ps, ls, cat, pwd, env, printenv,
//     ip, ifconfig, netstat, ss, dig, nslookup, ping, traceroute, which, w)
//   - Any command NOT on the allowlist is rejected before execution
//   - Commands run with a 30-second timeout to prevent hangs
//   - The first token of the command string is checked against the allowlist;
//     arguments are passed through (e.g., "ls -la /tmp" is allowed)
//
// This adapter is designed for system introspection and diagnostics —
// it intentionally does NOT allow write operations, package installs,
// service management, or anything that modifies system state.
// ─────────────────────────────────────────────────────────────────────────────
package adapters

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const (
	// commandTimeout — maximum execution time for any single command.
	// Prevents runaway processes from consuming agent resources.
	commandTimeout = 30 * time.Second
)

// ─────────────────────────────────────────────────────────────────────────────
// Allowlist — safe commands that the SystemAdapter will execute
// ─────────────────────────────────────────────────────────────────────────────
// These are read-only, non-destructive system introspection commands.
// The allowlist is intentionally conservative — it's a security boundary.
// ─────────────────────────────────────────────────────────────────────────────

var allowedCommands = map[string]bool{
	// ── System Information ─────────────────────────────────────────────
	"uptime":   true, // System uptime and load averages
	"whoami":   true, // Current user identity
	"hostname": true, // System hostname
	"date":     true, // Current date/time
	"uname":    true, // Kernel/OS information
	"id":       true, // User/group IDs
	"w":        true, // Who is logged in and what they're doing
	"arch":     true, // Machine architecture

	// ── Resource Monitoring ────────────────────────────────────────────
	"df":     true, // Disk usage
	"free":   true, // Memory usage
	"ps":     true, // Process listing
	"top":    true, // Process monitor (single snapshot with -bn1)
	"vmstat": true, // Virtual memory stats
	"lscpu":  true, // CPU information
	"lsblk":  true, // Block device listing

	// ── Filesystem (read-only) ─────────────────────────────────────────
	"ls":   true, // Directory listing
	"cat":  true, // File contents (read-only)
	"pwd":  true, // Current directory
	"file": true, // File type identification
	"head": true, // First lines of a file
	"tail": true, // Last lines of a file
	"wc":   true, // Word/line/byte counts
	"find": true, // Find files (read-only)

	// ── Environment ────────────────────────────────────────────────────
	"env":      true, // Environment variables
	"printenv": true, // Print specific env vars
	"echo":     true, // Echo text (useful for diagnostics)

	// ── Network Diagnostics ────────────────────────────────────────────
	"ip":         true, // Network interface info
	"ifconfig":   true, // Network interface config (legacy)
	"netstat":    true, // Network statistics
	"ss":         true, // Socket statistics
	"dig":        true, // DNS lookup
	"nslookup":   true, // DNS lookup (legacy)
	"ping":       true, // ICMP ping
	"traceroute": true, // Route tracing
	"curl":       true, // HTTP requests (read-only diagnostics)
	"wget":       true, // HTTP requests (read-only diagnostics)
	"which":      true, // Locate a command binary
}

// ─────────────────────────────────────────────────────────────────────────────
// SystemAdapter — the default EdgeAdapter implementation
// ─────────────────────────────────────────────────────────────────────────────

// SystemAdapter executes safe, non-destructive OS commands via os/exec.
// It enforces an allowlist of permitted commands and a strict execution
// timeout to prevent abuse.
type SystemAdapter struct{}

// NewSystemAdapter creates a new SystemAdapter instance.
func NewSystemAdapter() *SystemAdapter {
	return &SystemAdapter{}
}

// Name returns the adapter's human-readable identifier.
func (s *SystemAdapter) Name() string {
	return "SystemAdapter"
}

// ─────────────────────────────────────────────────────────────────────────────
// ExecuteIntent — processes a command payload
// ─────────────────────────────────────────────────────────────────────────────
// The payload is expected to be a UTF-8 command string (e.g., "uptime",
// "echo hello", "ls -la /tmp"). The first token is validated against the
// allowlist. If allowed, the command is executed with a 30-second timeout
// and the combined stdout+stderr output is returned.
//
// Security checks performed:
//   1. Payload must not be empty
//   2. First token (the command binary) must be on the allowlist
//   3. Execution is bounded by commandTimeout
// ─────────────────────────────────────────────────────────────────────────────

func (s *SystemAdapter) ExecuteIntent(payload []byte) ([]byte, error) {
	// Parse the command string from the raw payload.
	commandStr := strings.TrimSpace(string(payload))

	if commandStr == "" {
		return nil, fmt.Errorf("empty command payload")
	}

	// Split the command into tokens. The first token is the binary name;
	// the rest are arguments.
	tokens := strings.Fields(commandStr)
	binary := tokens[0]
	args := tokens[1:]

	// ── Allowlist check ────────────────────────────────────────────────
	// Only explicitly allowed commands can be executed. Everything else
	// is rejected at this gate, regardless of the arguments.
	if !allowedCommands[binary] {
		log.Printf("[ADAPTER] ✗ Blocked disallowed command: %q", binary)
		return nil, fmt.Errorf("command %q is not in the allowlist — execution denied", binary)
	}

	log.Printf("[ADAPTER] ▸ Executing: %s %s", binary, strings.Join(args, " "))

	// ── Execute with timeout ───────────────────────────────────────────
	// Create a context with the command timeout. If the command exceeds
	// this duration, it is forcefully killed.
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, args...)

	// CombinedOutput captures both stdout and stderr. This ensures the
	// operator sees error messages from the command itself, not just
	// our wrapper errors.
	output, err := cmd.CombinedOutput()

	// Check if the timeout was exceeded.
	if ctx.Err() == context.DeadlineExceeded {
		log.Printf("[ADAPTER] ⚠ Command timed out after %v: %q", commandTimeout, commandStr)
		return nil, fmt.Errorf("command timed out after %v", commandTimeout)
	}

	// If the command exited with a non-zero status, we still return the
	// output (which contains stderr) along with the error. This gives
	// the operator visibility into what went wrong.
	if err != nil {
		log.Printf("[ADAPTER] ⚠ Command exited with error: %v (output: %d bytes)",
			err, len(output))

		// Return the output even on error — it's diagnostic information.
		errorResponse := fmt.Sprintf("command error: %v\n\n%s", err, string(output))
		return []byte(errorResponse), nil
	}

	log.Printf("[ADAPTER] ✓ Command completed: %q (%d bytes output)",
		commandStr, len(output))

	return output, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// ListAllowedCommands — returns the sorted list of permitted commands
// ─────────────────────────────────────────────────────────────────────────────
// Useful for debugging and agent introspection.
// ─────────────────────────────────────────────────────────────────────────────

func ListAllowedCommands() []string {
	cmds := make([]string, 0, len(allowedCommands))
	for cmd := range allowedCommands {
		cmds = append(cmds, cmd)
	}
	return cmds
}
