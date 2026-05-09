# Changelog

All notable changes to Zero-Trust Hive are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-05-09

### Added

- **Gateway**: QUIC listener (UDP :443) with ephemeral mTLS certificate rotation
- **Gateway**: HTTP Control API (TCP :8080) with JWT authentication
- **Gateway**: Semantic Firewall with 15 regex rules blocking AI-hallucinated destructive commands
- **Gateway**: Thread-safe agent routing table with zero-zombie watchdog
- **Edge Agent**: Reverse QUIC tunnel with exponential backoff reconnection (1s → 60s cap)
- **Edge Agent**: Universal adapter interface with SystemAdapter (allowlist) and SidecarAdapter (HTTP/TCP proxy)
- **CLI**: `hive init`, `hive list`, `hive exec`, and `hive help` subcommands
- **CLI**: Lipgloss-based TUI with corporate design system and responsive banner
- **Auth**: JWT generation/validation (HMAC-SHA256, scoped claims, 24h expiry)
- **Auth**: Ephemeral in-memory RSA-2048 TLS certificate manager with hourly rotation
- Cross-platform builds (Linux, macOS, Windows) via GoReleaser
- Universal install scripts (bash, PowerShell)
- AI Agent demo (`examples/ai_agent_demo`) demonstrating happy path and firewall blocking

[0.1.0]: https://github.com/AhirTech1/zero-trust-hive/releases/tag/v0.1.0