package auth

import (
	"testing"
)

func TestAgentAuth_Enabled(t *testing.T) {
	a := NewAgentAuth("secret")
	if !a.Enabled() {
		t.Fatal("should be enabled when secret is provided")
	}

	b := NewAgentAuth("")
	if b.Enabled() {
		t.Fatal("should be disabled when secret is empty")
	}
}

func TestAgentAuth_Validate_Success(t *testing.T) {
	secret := "shared-agent-secret"
	a := NewAgentAuth(secret)

	mac := ComputeMAC("agent-007", secret)
	payload := "agent-007\n" + mac

	id, err := a.ValidateAgentID(payload)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if id != "agent-007" {
		t.Errorf("got agent ID %q, want %q", id, "agent-007")
	}
}

func TestAgentAuth_Validate_WrongSecret(t *testing.T) {
	a := NewAgentAuth("secret-a")
	mac := ComputeMAC("agent-007", "secret-b") // wrong secret
	payload := "agent-007\n" + mac

	_, err := a.ValidateAgentID(payload)
	if err == nil {
		t.Fatal("expected error with wrong secret MAC")
	}
}

func TestAgentAuth_Validate_WrongID(t *testing.T) {
	a := NewAgentAuth("secret")

	// MAC for "agent-007" but claiming to be "agent-008"
	mac := ComputeMAC("agent-007", "secret")
	payload := "agent-008\n" + mac

	_, err := a.ValidateAgentID(payload)
	if err == nil {
		t.Fatal("expected error when MAC doesn't match claimed ID")
	}
}

func TestAgentAuth_Validate_Disabled(t *testing.T) {
	a := NewAgentAuth("")

	// When auth is disabled, any string is accepted as the agent ID
	id, err := a.ValidateAgentID("any-agent-id")
	if err != nil {
		t.Fatalf("disabled auth should accept any ID: %v", err)
	}
	if id != "any-agent-id" {
		t.Errorf("got %q, want %q", id, "any-agent-id")
	}
}

func TestAgentAuth_Validate_Malformed(t *testing.T) {
	a := NewAgentAuth("secret")

	_, err := a.ValidateAgentID("no-newline")
	if err == nil {
		t.Fatal("expected error for malformed payload (no newline)")
	}
}

func TestAgentAuth_Validate_EmptyID(t *testing.T) {
	a := NewAgentAuth("secret")

	mac := ComputeMAC("", "secret")
	payload := "\n" + mac

	_, err := a.ValidateAgentID(payload)
	if err == nil {
		t.Fatal("expected error for empty agent ID")
	}
}

func TestComputeMAC_Deterministic(t *testing.T) {
	m1 := ComputeMAC("agent-001", "secret")
	m2 := ComputeMAC("agent-001", "secret")
	if m1 != m2 {
		t.Fatal("MAC should be deterministic")
	}
}

func TestComputeMAC_DifferentPerID(t *testing.T) {
	m1 := ComputeMAC("agent-001", "secret")
	m2 := ComputeMAC("agent-002", "secret")
	if m1 == m2 {
		t.Fatal("different IDs should produce different MACs")
	}
}

func TestComputeMAC_DifferentPerSecret(t *testing.T) {
	m1 := ComputeMAC("agent-001", "secret-a")
	m2 := ComputeMAC("agent-001", "secret-b")
	if m1 == m2 {
		t.Fatal("different secrets should produce different MACs")
	}
}

func TestAgentAuth_Roundtrip(t *testing.T) {
	secret := "roundtrip-secret"
	agentID := "edge-node-west-1"

	// Agent side: compute MAC
	mac := ComputeMAC(agentID, secret)
	payload := agentID + "\n" + mac

	// Gateway side: validate
	a := NewAgentAuth(secret)
	validatedID, err := a.ValidateAgentID(payload)
	if err != nil {
		t.Fatalf("roundtrip failed: %v", err)
	}
	if validatedID != agentID {
		t.Errorf("roundtrip: got %q, want %q", validatedID, agentID)
	}
}