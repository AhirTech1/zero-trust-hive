package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for Zero-Trust Hive components.
// All values are loaded from environment variables with sensible defaults.
type Config struct {
	// JWTSecret is the HMAC-SHA256 signing key shared by Gateway, CLI, and AI agents.
	JWTSecret string

	// GatewayURL is the HTTP address the CLI uses to reach the Gateway API.
	GatewayURL string

	// QUICListenAddr is the UDP address the Gateway's QUIC listener binds to.
	QUICListenAddr string

	// APIListenAddr is the TCP address the Gateway's HTTP control API binds to.
	APIListenAddr string

	// AgentID is the unique identifier this agent registers with.
	AgentID string

	// AgentSecret is the pre-shared key for agent-to-gateway authentication.
	// When set, the agent must HMAC its ID to prove possession of the secret.
	AgentSecret string

	// CommandTimeout is the maximum time to wait for an agent to respond.
	CommandTimeout time.Duration

	// RateLimit is the maximum requests per minute per JWT subject.
	RateLimit int

	// AdapterMode controls how the SystemAdapter handles commands.
	// "allowlist" — only execute commands on the allowlist.
	// "passthrough" — execute any command, relying on firewall for safety.
	AdapterMode string

	// AllowlistCommands is a comma-separated list of additional commands
	// to add to the SystemAdapter allowlist.
	AllowlistCommands string

	// LogFormat controls log output: "text" or "json".
	LogFormat string

	// AuditLog enables structured JSON audit logging to stderr when true.
	AuditLog bool
}

// LoadFromEnv reads configuration from environment variables.
// Returns a Config with defaults set for any unset variables.
func LoadFromEnv() *Config {
	return &Config{
		JWTSecret:         envOrDefault("HIVE_JWT_SECRET", ""),
		GatewayURL:        envOrDefault("HIVE_GATEWAY_URL", "http://localhost:8080"),
		QUICListenAddr:    envOrDefault("HIVE_QUIC_LISTEN_ADDR", "0.0.0.0:443"),
		APIListenAddr:     envOrDefault("HIVE_API_LISTEN_ADDR", "0.0.0.0:8080"),
		AgentID:           envOrDefault("HIVE_AGENT_ID", "agent-001"),
		AgentSecret:       envOrDefault("HIVE_AGENT_SECRET", ""),
		CommandTimeout:    envDurationOrDefault("HIVE_COMMAND_TIMEOUT", 5*time.Second),
		RateLimit:         envIntOrDefault("HIVE_RATE_LIMIT", 60),
		AdapterMode:       envOrDefault("HIVE_ADAPTER_MODE", "allowlist"),
		AllowlistCommands: envOrDefault("HIVE_ALLOWLIST_COMMANDS", ""),
		LogFormat:         envOrDefault("HIVE_LOG_FORMAT", "text"),
		AuditLog:          envBoolOrDefault("HIVE_AUDIT_LOG", false),
	}
}

func envOrDefault(key, defaultVal string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return defaultVal
}

func envDurationOrDefault(key string, defaultVal time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return defaultVal
}

func envIntOrDefault(key string, defaultVal int) int {
	if v, ok := os.LookupEnv(key); ok {
		n, err := strconv.Atoi(v)
		if err == nil && n > 0 {
			return n
		}
	}
	return defaultVal
}

func envBoolOrDefault(key string, defaultVal bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return defaultVal
}