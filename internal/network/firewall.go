// ─────────────────────────────────────────────────────────────────────────────
// Package network — Semantic Firewall (AI Hallucination Guard)
// ─────────────────────────────────────────────────────────────────────────────
// The SemanticFirewall inspects every command payload dispatched by AI agents
// and human operators before it enters the QUIC tunnel to an Edge Agent.
//
// AI agents (LLMs) hallucinate. When an LLM autonomously generates shell
// commands or SQL queries, a single hallucinated `rm -rf /` or `DROP TABLE`
// can destroy production infrastructure. This firewall is the last line of
// defense — it pattern-matches against 14+ categories of destructive
// operations and blocks them at the Gateway level.
//
// Blocked Categories:
//   - Recursive/forced deletions (rm -rf, rm -f /*)
//   - Database drops (DROP TABLE, DROP DATABASE, TRUNCATE, DELETE)
//   - Filesystem formatters (mkfs, fdisk, dd)
//   - Fork bombs (:(){ :|:& };:)
//   - Privilege escalation (GRANT, REVOKE, chmod on /)
//   - System shutdown (shutdown, reboot, init 0)
//   - Credential exfiltration (PASSWORD keywords)
//   - Block device writes (> /dev/sda)
//
// ─────────────────────────────────────────────────────────────────────────────
package network

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// FirewallRule — a single pattern + metadata
// ─────────────────────────────────────────────────────────────────────────────

// FirewallRule defines a single destructive pattern the firewall checks.
type FirewallRule struct {
	// Pattern is the compiled regex that matches the destructive keyword.
	Pattern *regexp.Regexp

	// Category describes the threat class (e.g., "SQL", "Bash", "System").
	Category string

	// Description is a human-readable explanation of what the pattern catches.
	Description string

	// Severity is the threat level: "critical", "high", "medium".
	Severity string
}

// FirewallVerdict is the result of a firewall inspection.
type FirewallVerdict struct {
	// Allowed is true if the command passed all checks.
	Allowed bool `json:"allowed"`

	// Violations is the list of rules that were triggered.
	Violations []FirewallViolation `json:"violations,omitempty"`
}

// FirewallViolation describes a single rule that was triggered.
type FirewallViolation struct {
	Category    string `json:"category"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Matched     string `json:"matched"`
}

// ─────────────────────────────────────────────────────────────────────────────
// SemanticFirewall — the main firewall struct
// ─────────────────────────────────────────────────────────────────────────────

// SemanticFirewall inspects command payloads for destructive patterns.
// It is thread-safe and tracks inspection statistics.
type SemanticFirewall struct {
	mu    sync.RWMutex
	rules []FirewallRule

	// Statistics
	totalInspected uint64
	totalBlocked   uint64
}

// ─────────────────────────────────────────────────────────────────────────────
// Default Rules — the built-in hallucination guard ruleset
// ─────────────────────────────────────────────────────────────────────────────

var defaultRules = []FirewallRule{
	// ── Category 1: Recursive/Forced Deletions ─────────────────────────
	{
		Pattern:     regexp.MustCompile(`(?i)\brm\s+(-[rRf]+\s+|.*--no-preserve-root)`),
		Category:    "Bash",
		Description: "rm with recursive/force flags",
		Severity:    "critical",
	},

	// ── Category 2: Database Drops ─────────────────────────────────────
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

	// ── Category 3: Filesystem Formatters ──────────────────────────────
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

	// ── Category 4: Fork Bombs ─────────────────────────────────────────
	{
		Pattern:     regexp.MustCompile(`:\(\)\s*\{\s*:\|:\s*&\s*\}\s*;:`),
		Category:    "Bash",
		Description: "Fork bomb (resource exhaustion attack)",
		Severity:    "critical",
	},

	// ── Additional: Privilege Escalation ───────────────────────────────
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

	// ── Additional: Credential Exfiltration ────────────────────────────
	{
		Pattern:     regexp.MustCompile(`(?i)\bPASSWORDS?\b`),
		Category:    "SQL",
		Description: "PASSWORD keyword (credential exfiltration attempt)",
		Severity:    "high",
	},

	// ── Additional: Block Device Writes ────────────────────────────────
	{
		Pattern:     regexp.MustCompile(`(?i)>\s*/dev/[sh]da`),
		Category:    "Bash",
		Description: "Direct write to block device (disk destruction)",
		Severity:    "critical",
	},

	// ── Additional: System Control ─────────────────────────────────────
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
}

// ─────────────────────────────────────────────────────────────────────────────
// NewSemanticFirewall — constructor
// ─────────────────────────────────────────────────────────────────────────────

// NewSemanticFirewall creates a firewall with the default hallucination guard
// ruleset. Additional custom rules can be added with AddRule().
func NewSemanticFirewall() *SemanticFirewall {
	fw := &SemanticFirewall{
		rules: make([]FirewallRule, len(defaultRules)),
	}
	copy(fw.rules, defaultRules)

	log.Printf("[FIREWALL] ✓ Semantic Firewall initialized — %d rules loaded", len(fw.rules))
	return fw
}

// AddRule appends a custom rule to the firewall at runtime.
func (fw *SemanticFirewall) AddRule(rule FirewallRule) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	fw.rules = append(fw.rules, rule)
}

// ─────────────────────────────────────────────────────────────────────────────
// Inspect — the firewall's primary inspection method
// ─────────────────────────────────────────────────────────────────────────────
// Returns nil if the command is safe, or an error with a structured
// description if it is blocked. The error message is designed to be
// directly parsable by AI agents.
// ─────────────────────────────────────────────────────────────────────────────

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

			log.Printf("[FIREWALL] 🛡 BLOCKED [%s/%s]: %s — matched: %q (inspected: %d, blocked: %d)",
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

// ─────────────────────────────────────────────────────────────────────────────
// InspectVerbose — returns ALL violations (not just the first)
// ─────────────────────────────────────────────────────────────────────────────
// Returns a full FirewallVerdict with all triggered rules. Useful for
// audit logging and AI agent feedback.
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// Stats — returns firewall statistics
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// Legacy compatibility — InspectPayload wraps the default firewall
// ─────────────────────────────────────────────────────────────────────────────

var defaultFirewall = NewSemanticFirewall()

// InspectPayload is a package-level convenience function that uses the
// default SemanticFirewall instance. Kept for backward compatibility.
func InspectPayload(command string) error {
	return defaultFirewall.Inspect(command)
}

// InspectPayloadVerbose is a package-level convenience function that uses
// the default SemanticFirewall instance for verbose inspection.
func InspectPayloadVerbose(command string) FirewallVerdict {
	return defaultFirewall.InspectVerbose(command)
}
