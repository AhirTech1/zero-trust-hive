<div align="center">

# Zero-Trust Hive

<pre>
███████╗███████╗██████╗  ██████╗       ████████╗██████╗ ██╗   ██╗███████╗████████╗
╚══███╔╝██╔════╝██╔══██╗██╔═══██╗      ╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
	███╔╝ █████╗  ██████╔╝██║   ██║█████╗   ██║   ██████╔╝██║   ██║███████╗   ██║   
 ███╔╝  ██╔══╝  ██╔══██╗██║   ██║╚════╝   ██║   ██╔══██╗██║   ██║╚════██║   ██║   
███████╗███████╗██║  ██║╚██████╔╝         ██║   ██║  ██║╚██████╔╝███████║   ██║   
╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝          ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   

██╗  ██╗██╗██╗   ██╗███████╗
██║  ██║██║██║   ██║██╔════╝
███████║██║██║   ██║█████╗  
██╔══██║██║╚██╗ ██╔╝██╔══╝  
██║  ██║██║ ╚████╔╝ ███████╗
╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝
</pre>

Distributed command execution over QUIC with cryptographic identity, policy-first routing, and protocol envelopes.

![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat-square&logo=go&logoColor=white)
![Transport](https://img.shields.io/badge/Transport-QUIC-111111?style=flat-square)
![Security](https://img.shields.io/badge/Security-mTLS-0A0A0A?style=flat-square)
![Policy](https://img.shields.io/badge/Policy-Semantic%20Firewall-151515?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-1F1F1F?style=flat-square)

</div>

## Architecture

```mermaid
flowchart LR
		CLI[Operator CLI] -->|POST /execute| FW[Semantic Firewall]
		FW -->|allow| GW[Gateway Router]
		GW -->|QUIC + TLS1.3 (UDP :443)| AG[Edge Agent]
		AG --> AD[Execution Adapter]
		AD --> OUT[Command Output]
```

## Core Engine

- **QUIC Transport** — low-latency, long-lived, stream-multiplexed control channels.
- **mTLS Identity** — ephemeral in-memory certificates with automatic rotation.
- **Semantic Firewall** — pre-dispatch payload inspection for destructive patterns.
- **Envelope Proxy** — structured routing envelopes for local HTTP/TCP forwarding.

## Quickstart

```bash
curl -fsSL https://github.com/zero-trust-hive/cli/archive/refs/heads/main.tar.gz | tar -xz
cd cli-main

go build -o bin/hive ./cmd/cli
go build -o bin/hive-gateway ./cmd/gateway
go build -o bin/hive-agent ./cmd/agent

export HIVE_API_TOKEN="dev-token"

./bin/hive-gateway
# new terminal:
./bin/hive-agent -gateway 127.0.0.1:443 -id agent-001

./bin/hive list
./bin/hive exec -target agent-001 -cmd 'uptime'
```

## The Protocol

```json
{
	"routing": {
		"protocol": "http",
		"target": "127.0.0.1:8080"
	},
	"payload_format": "json",
	"payload": "{\"op\":\"health\"}"
}
```

```bash
ENVELOPE='{"routing":{"protocol":"http","target":"127.0.0.1:8080"},"payload_format":"json","payload":"{\"op\":\"health\"}"}'
./bin/hive exec -target agent-001 -cmd "$ENVELOPE"
```

## Control API

- `POST /execute` — send command payload to an agent.
- `GET /agents` — enumerate active agents and uptime.
- `GET /health` — gateway health and active connection state.
