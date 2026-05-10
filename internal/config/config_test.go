package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadFromEnv_Defaults(t *testing.T) {
	cfg := LoadFromEnv()

	if cfg.GatewayURL != "http://localhost:8080" {
		t.Errorf("GatewayURL = %q, want default", cfg.GatewayURL)
	}
	if cfg.QUICListenAddr != "0.0.0.0:443" {
		t.Errorf("QUICListenAddr = %q, want default", cfg.QUICListenAddr)
	}
	if cfg.APIListenAddr != "0.0.0.0:8080" {
		t.Errorf("APIListenAddr = %q, want default", cfg.APIListenAddr)
	}
	if cfg.AgentID != "agent-001" {
		t.Errorf("AgentID = %q, want agent-001", cfg.AgentID)
	}
	if cfg.CommandTimeout != 5*time.Second {
		t.Errorf("CommandTimeout = %v, want 5s", cfg.CommandTimeout)
	}
	if cfg.RateLimit != 60 {
		t.Errorf("RateLimit = %d, want 60", cfg.RateLimit)
	}
	if cfg.AdapterMode != "allowlist" {
		t.Errorf("AdapterMode = %q, want allowlist", cfg.AdapterMode)
	}
	if cfg.AuditLog != false {
		t.Errorf("AuditLog = %v, want false", cfg.AuditLog)
	}
}

func TestLoadFromEnv_Overrides(t *testing.T) {
	os.Setenv("HIVE_GATEWAY_URL", "https://gateway.example.com:9090")
	os.Setenv("HIVE_AGENT_ID", "prod-agent-07")
	os.Setenv("HIVE_COMMAND_TIMEOUT", "30s")
	os.Setenv("HIVE_RATE_LIMIT", "120")
	os.Setenv("HIVE_ADAPTER_MODE", "passthrough")
	os.Setenv("HIVE_AUDIT_LOG", "true")
	os.Setenv("HIVE_AGENT_SECRET", "super-secret-key")
	defer func() {
		for _, k := range []string{
			"HIVE_GATEWAY_URL", "HIVE_AGENT_ID", "HIVE_COMMAND_TIMEOUT",
			"HIVE_RATE_LIMIT", "HIVE_ADAPTER_MODE", "HIVE_AUDIT_LOG", "HIVE_AGENT_SECRET",
		} {
			os.Unsetenv(k)
		}
	}()

	cfg := LoadFromEnv()

	if cfg.GatewayURL != "https://gateway.example.com:9090" {
		t.Errorf("GatewayURL = %q", cfg.GatewayURL)
	}
	if cfg.AgentID != "prod-agent-07" {
		t.Errorf("AgentID = %q", cfg.AgentID)
	}
	if cfg.CommandTimeout != 30*time.Second {
		t.Errorf("CommandTimeout = %v", cfg.CommandTimeout)
	}
	if cfg.RateLimit != 120 {
		t.Errorf("RateLimit = %d", cfg.RateLimit)
	}
	if cfg.AdapterMode != "passthrough" {
		t.Errorf("AdapterMode = %q", cfg.AdapterMode)
	}
	if !cfg.AuditLog {
		t.Error("AuditLog should be true")
	}
	if cfg.AgentSecret != "super-secret-key" {
		t.Errorf("AgentSecret = %q", cfg.AgentSecret)
	}
}

func TestLoadFromEnv_InvalidValues(t *testing.T) {
	os.Setenv("HIVE_COMMAND_TIMEOUT", "not-a-duration")
	os.Setenv("HIVE_RATE_LIMIT", "-1")
	os.Setenv("HIVE_AUDIT_LOG", "maybe")
	defer func() {
		os.Unsetenv("HIVE_COMMAND_TIMEOUT")
		os.Unsetenv("HIVE_RATE_LIMIT")
		os.Unsetenv("HIVE_AUDIT_LOG")
	}()

	cfg := LoadFromEnv()

	if cfg.CommandTimeout != 5*time.Second {
		t.Errorf("invalid CommandTimeout should fall back to default, got %v", cfg.CommandTimeout)
	}
	if cfg.RateLimit != 60 {
		t.Errorf("invalid RateLimit should fall back to default, got %d", cfg.RateLimit)
	}
	if cfg.AuditLog != false {
		t.Errorf("invalid AuditLog should fall back to default, got %v", cfg.AuditLog)
	}
}