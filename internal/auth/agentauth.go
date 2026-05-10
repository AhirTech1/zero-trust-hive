package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// AgentAuth provides HMAC-based agent identity verification.
// The agent proves possession of the shared secret by sending
// its ID + an HMAC-SHA256(agentID, secret) in the identification stream.
type AgentAuth struct {
	secret []byte
}

// NewAgentAuth creates an AgentAuth. If secret is empty, authentication
// is disabled and all agents are accepted (backward compatible).
func NewAgentAuth(secret string) *AgentAuth {
	if secret == "" {
		return &AgentAuth{secret: nil}
	}
	return &AgentAuth{secret: []byte(secret)}
}

// Enabled returns true if agent authentication is active.
func (a *AgentAuth) Enabled() bool {
	return a.secret != nil
}

// ComputeMAC returns the hex-encoded HMAC-SHA256 for the given agent ID.
// The agent calls this to produce the authentication payload.
func ComputeMAC(agentID, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(agentID))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidateAgentID validates a raw identification payload from an agent.
// The payload format is: "agentID\n<HMAC-SHA256>"
// If authentication is disabled (no secret), any ID is accepted.
// Returns the validated agent ID or an error.
func (a *AgentAuth) ValidateAgentID(payload string) (string, error) {
	if !a.Enabled() {
		return payload, nil
	}

	parts := strings.SplitN(payload, "\n", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid agent auth format: expected 'id\\nhmac'")
	}

	agentID := strings.TrimSpace(parts[0])
	providedMAC := strings.TrimSpace(parts[1])

	if agentID == "" {
		return "", fmt.Errorf("empty agent ID")
	}

	expectedMAC := ComputeMAC(agentID, string(a.secret))
	if !hmac.Equal([]byte(providedMAC), []byte(expectedMAC)) {
		return "", fmt.Errorf("agent authentication failed for %q: invalid HMAC", agentID)
	}

	return agentID, nil
}