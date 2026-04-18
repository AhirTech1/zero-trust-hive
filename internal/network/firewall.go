// ─────────────────────────────────────────────────────────────────────────────
// Package network — Semantic Firewall
// ─────────────────────────────────────────────────────────────────────────────
// Inspects incoming command payloads before they are forwarded to Edge Agents.
// Blocks any command containing destructive SQL keywords, dangerous Bash
// commands, or other patterns that could indicate a supply-chain attack or
// accidental destructive operation.
//
// This is a defense-in-depth layer — even if an operator has a valid Bearer
// token, they cannot issue destructive commands through the Gateway.
// ─────────────────────────────────────────────────────────────────────────────
package network

import (
	"fmt"
	"regexp"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// Blocked Patterns
// ─────────────────────────────────────────────────────────────────────────────
// Each pattern is a compiled regex with word-boundary awareness and case-
// insensitive matching. We split them into SQL and Bash categories for
// clear logging when a violation is detected.
// ─────────────────────────────────────────────────────────────────────────────

// blockedPattern holds a compiled regex and its category for logging.
type blockedPattern struct {
	// pattern is the compiled regex that matches the destructive keyword.
	pattern *regexp.Regexp

	// category describes the type of threat (e.g., "SQL", "Bash").
	category string

	// description is a human-readable explanation of what the pattern catches.
	description string
}

// blockedPatterns is the master list of all patterns the firewall checks.
// Patterns use (?i) for case-insensitive matching and \b for word boundaries
// to reduce false positives.
var blockedPatterns = []blockedPattern{
	// ── Destructive SQL keywords ───────────────────────────────────────
	{
		pattern:     regexp.MustCompile(`(?i)\bDROP\b`),
		category:    "SQL",
		description: "DROP statement (table/database destruction)",
	},
	{
		pattern:     regexp.MustCompile(`(?i)\bDELETE\b`),
		category:    "SQL",
		description: "DELETE statement (record destruction)",
	},
	{
		pattern:     regexp.MustCompile(`(?i)\bTRUNCATE\b`),
		category:    "SQL",
		description: "TRUNCATE statement (table wipe)",
	},
	{
		pattern:     regexp.MustCompile(`(?i)\bPASSWORDS?\b`),
		category:    "SQL",
		description: "PASSWORD/PASSWORDS keyword (credential exfiltration)",
	},
	{
		pattern:     regexp.MustCompile(`(?i)\bALTER\s+TABLE\b`),
		category:    "SQL",
		description: "ALTER TABLE statement (schema modification)",
	},
	{
		pattern:     regexp.MustCompile(`(?i)\bGRANT\b`),
		category:    "SQL",
		description: "GRANT statement (privilege escalation)",
	},
	{
		pattern:     regexp.MustCompile(`(?i)\bREVOKE\b`),
		category:    "SQL",
		description: "REVOKE statement (privilege manipulation)",
	},

	// ── Destructive Bash/Shell commands ────────────────────────────────
	{
		pattern:     regexp.MustCompile(`(?i)\brm\s+(-[rRf]+\s+|.*--no-preserve-root)`),
		category:    "Bash",
		description: "rm with recursive/force flags (filesystem destruction)",
	},
	{
		pattern:     regexp.MustCompile(`(?i)\bmkfs\b`),
		category:    "Bash",
		description: "mkfs command (filesystem format)",
	},
	{
		pattern:     regexp.MustCompile(`(?i)\bdd\s+if=`),
		category:    "Bash",
		description: "dd with input file (raw disk write)",
	},
	{
		pattern:     regexp.MustCompile(`:\(\)\s*\{\s*:\|:\s*&\s*\}\s*;:`),
		category:    "Bash",
		description: "Fork bomb (resource exhaustion)",
	},
	{
		pattern:     regexp.MustCompile(`(?i)>\s*/dev/[sh]da`),
		category:    "Bash",
		description: "Direct write to block device (disk destruction)",
	},
	{
		pattern:     regexp.MustCompile(`(?i)\bchmod\s+(-[rR]+\s+)?[0-7]{3,4}\s+/`),
		category:    "Bash",
		description: "chmod on root paths (permission manipulation)",
	},
	{
		pattern:     regexp.MustCompile(`(?i)\bshutdown\b|\breboot\b|\binit\s+0\b`),
		category:    "Bash",
		description: "System shutdown/reboot command",
	},
}

// ─────────────────────────────────────────────────────────────────────────────
// InspectPayload — the firewall's public entry point
// ─────────────────────────────────────────────────────────────────────────────
// Inspects a command string against all blocked patterns. Returns nil if the
// command is clean, or a descriptive error if a violation is detected.
//
// The error message includes:
//   - The category of the violation (SQL / Bash)
//   - The specific pattern that was triggered
//   - The matched substring for forensic logging
//
// Example:
//
//	err := InspectPayload("SELECT * FROM users; DROP TABLE users;")
//	// err: "BLOCKED [SQL]: DROP statement (...) — matched: 'DROP'"
// ─────────────────────────────────────────────────────────────────────────────

func InspectPayload(command string) error {
	// Normalize the command for consistent matching.
	normalized := strings.TrimSpace(command)

	if normalized == "" {
		return fmt.Errorf("empty command payload")
	}

	// Check every pattern in the blocklist.
	for _, bp := range blockedPatterns {
		match := bp.pattern.FindString(normalized)
		if match != "" {
			return fmt.Errorf(
				"BLOCKED [%s]: %s — matched: %q in command payload",
				bp.category, bp.description, match,
			)
		}
	}

	// No violations detected — command is clean.
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// InspectPayloadVerbose — returns all violations (not just the first)
// ─────────────────────────────────────────────────────────────────────────────
// Useful for audit logging where you want to know every violation in a single
// payload, not just the first one that triggered.
// ─────────────────────────────────────────────────────────────────────────────

func InspectPayloadVerbose(command string) []string {
	normalized := strings.TrimSpace(command)
	var violations []string

	for _, bp := range blockedPatterns {
		match := bp.pattern.FindString(normalized)
		if match != "" {
			violations = append(violations, fmt.Sprintf(
				"[%s] %s (matched: %q)", bp.category, bp.description, match,
			))
		}
	}

	return violations
}
