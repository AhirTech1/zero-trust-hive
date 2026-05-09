<div align="center">

<pre>
███████╗███████╗██████╗  ██████╗       ████████╗██████╗ ██╗   ██╗███████╗████████╗
╚══███╔╝██╔════╝██╔══██╗██╔═══██╗      ╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
  ███╔╝ █████╗  ██████╔╝██║   ██║         ██║   ██████╔╝██║   ██║███████╗   ██║   
 ███╔╝  ██╔══╝  ██╔══██╗██║   ██║         ██║   ██╔══██╗██║   ██║╚════██║   ██║   
███████╗███████╗██║  ██║╚██████╔╝         ██║   ██║  ██║╚██████╔╝███████║   ██║   
╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝          ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
                   ██╗  ██╗██╗██╗   ██╗███████╗
                   ██║  ██║██║██║   ██║██╔════╝
                   ███████║██║██║   ██║█████╗  
                   ██╔══██║██║╚██╗ ██╔╝██╔══╝  
                   ██║  ██║██║ ╚████╔╝ ███████╗
                   ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝
</pre>

**`ngrok` for AI Agents — A zero-trust execution tunnel that lets cloud AI agents safely operate on your private infrastructure.**

[![Go Version](https://img.shields.io/github/go-mod/go-version/AhirTech1/zero-trust-hive)](https://golang.org/doc/devel/release.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/AhirTech1/zero-trust-hive/actions/workflows/ci.yml/badge.svg)](https://github.com/AhirTech1/zero-trust-hive/actions)
[![Release](https://img.shields.io/github/v/release/AhirTech1/zero-trust-hive?include_prereleases)](https://github.com/AhirTech1/zero-trust-hive/releases)

</div>

---

## Table of Contents

- [The Problem](#the-problem)
- [The Solution](#the-solution)
- [Architecture](#architecture)
- [Security Architecture](#security-architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Try the Demo](#try-the-demo)
- [API Reference](#api-reference)
- [Contributing](#contributing)
- [Security](#security)
- [Community](#community)
- [License](#license)

---

## The Problem

AI agents built with LangChain, AutoGPT, CrewAI, or Claude Computer Use live in the cloud. But the data they need to act on — databases, filesystems, internal APIs — lives on **your** private machines, behind firewalls, NATs, and air-gapped networks.

Today, connecting them requires punching holes in your firewall, exposing SSH ports, or maintaining fragile VPN tunnels. **Every open port is an attack surface.** And worse — LLMs hallucinate. A single hallucinated `rm -rf /` or `DROP TABLE users` can destroy your production environment.

## The Solution

**Zero-Trust Hive** creates a persistent, reverse QUIC tunnel from your private machine *out* to a cloud gateway. Your AI agent authenticates with a **signed JWT**, sends execution requests to the gateway's HTTP API, and a **Semantic Firewall** inspects every command *before* it enters the tunnel — automatically blocking hallucinated destructive operations. Only validated, safe instructions reach your machine.

**No inbound ports. No SSH. No VPN. No exposed attack surface.**

---

## Architecture

```mermaid
flowchart LR
    classDef agent fill:#6C3483,stroke:#ECF0F1,stroke-width:2px,color:#ECF0F1;
    classDef cloud fill:#1B2A4A,stroke:#3498DB,stroke-width:2px,color:#ECF0F1;
    classDef firewall fill:#922B21,stroke:#E74C3C,stroke-width:2px,color:#ECF0F1;
    classDef edge fill:#2C3E50,stroke:#27AE60,stroke-width:2px,color:#ECF0F1;
    classDef target fill:#111111,stroke:#E67E22,stroke-width:2px,color:#ECF0F1;

    AI["Cloud AI Agent<br/>(LangChain / AutoGPT / Claude)"]:::agent

    subgraph Gateway ["Zero-Trust Hive Gateway (Cloud Server)"]
        JWT["JWT Auth (HMAC-SHA256)"]:::cloud
        FW["Semantic Firewall (15 Regex Rules)"]:::firewall
        API["Control API (TCP 8080)"]:::cloud
        QUICGW["QUIC Endpoint (UDP 443)"]:::cloud
    end

    subgraph Private ["Your Private Network (Zero Inbound Ports)"]
        EdgeAgent["Hive Edge Agent"]:::edge
        Sidecar["Sidecar Proxy"]:::edge
        DB["Private DB / API / FS"]:::target
    end

    AI -->|"POST /execute + JWT"| JWT
    JWT -->|"Claims Validated"| API
    API -->|"Inspect Command"| FW
    FW -.->|"Safe — Forward"| QUICGW
    FW -.->|"Blocked — HTTP 403"| AI

    EdgeAgent <-->|"Encrypted mTLS QUIC Tunnel<br/>(Ephemeral Certs, Hourly Rotation)"| QUICGW

    EdgeAgent -->|"Execute / Proxy"| Sidecar
    Sidecar -->|"localhost Only"| DB
```

The system ships as three purpose-built Go binaries:

| Binary | Role | Where It Runs |
|:-------|:-----|:--------------|
| **`gateway`** | JWT-authenticated API, Semantic Firewall, QUIC listener | Your cloud server (public IP) |
| **`agent`** | Reverse tunnel anchor, local execution & sidecar proxy | Your private machine (no inbound ports) |
| **`hive`** | Operator CLI for bootstrapping, fleet monitoring, and dispatch | Your laptop / CI pipeline |

---

## Security Architecture

Zero-Trust Hive enforces **three layers of security** on every request:

### Layer 1: JWT Authentication (HMAC-SHA256)

Every API request must carry a signed JWT in the `Authorization: Bearer <token>` header. Tokens are cryptographically signed, scoped (`execute`, `read`, `admin`), and expire after 24 hours.

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
                      └── sub: "langchain-agent"
                      └── scope: "execute"  
                      └── exp: 1713628800
```

### Layer 2: Semantic Firewall (AI Hallucination Guard)

The Semantic Firewall uses **15 compiled regular expressions** to intercept destructive commands at the Gateway *before* they enter the QUIC tunnel:

| Category | Blocked Patterns | Severity |
|:---------|:-----------------|:---------|
| **Recursive Deletions** | `rm -rf`, `rm -f /*`, `--no-preserve-root` | Critical |
| **Database Drops** | `DROP TABLE`, `DROP DATABASE`, `TRUNCATE`, `DELETE FROM` | Critical |
| **Filesystem Formatters** | `mkfs`, `fdisk`, `dd if=` | Critical |
| **Fork Bombs** | `:(){ :\|:& };:` | Critical |
| **Block Device Writes** | `> /dev/sda`, `> /dev/hda` | Critical |
| **Privilege Escalation** | `GRANT ALL`, `REVOKE`, `ALTER TABLE` | High |
| **System Control** | `shutdown`, `reboot`, `init 0` | High |
| **Credential Exfiltration** | `PASSWORD`, `PASSWORDS` | High |
| **Permission Manipulation** | `chmod 777 /`, `chmod -R` on root paths | High |

### Layer 3: Ephemeral In-Memory Cryptography

All mTLS certificates are RSA 2048, generated in RAM at boot, and rotated hourly via a background goroutine. **Private keys never touch disk.** QUIC tunnel enforces TLS 1.3 minimum.

### Zero-Inbound Architecture

The Edge Agent initiates an **outbound-only** QUIC connection over UDP 443. Your private machine opens **zero listening ports** — invisible to Shodan, Censys, and any external scanner.

---

## Installation

### Automated Install (Recommended)

**Linux / macOS:**
```bash
curl -sSfL https://raw.githubusercontent.com/AhirTech1/zero-trust-hive/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
iwr https://raw.githubusercontent.com/AhirTech1/zero-trust-hive/main/install.ps1 -useb | iex
```

### Docker

```bash
docker build -t zero-trust-hive .
docker run -p 443:443/udp -p 8080:8080 -e HIVE_JWT_SECRET="your-secret" zero-trust-hive
```

### Build from Source

Requires [Go 1.26+](https://go.dev/dl/).

```bash
git clone https://github.com/AhirTech1/zero-trust-hive.git
cd zero-trust-hive
make build
```

---

## Quick Start

### 1. Bootstrap Configuration

```bash
./bin/hive init
```

Generates `.env` with `HIVE_JWT_SECRET` (64-char hex) and a pre-signed admin JWT.

### 2. Start the Gateway

```bash
export HIVE_JWT_SECRET="<your_secret_from_.env>"
sudo -E ./bin/gateway
```

### 3. Connect an Edge Agent

```bash
./bin/agent -gateway <GATEWAY_IP>:443 -id my-private-server
```

### 4. Execute Commands

**From the CLI:**
```bash
export HIVE_JWT_SECRET="<your_secret>"
hive list
hive exec -target my-private-server -cmd "uptime"
```

**From your AI Agent — any language, just HTTP:**
```http
POST http://<GATEWAY_IP>:8080/execute
Authorization: Bearer <signed_jwt>
Content-Type: application/json

{"agent_id": "my-private-server", "command": "cat /var/log/app/errors.log | tail -50"}
```

---

## Try the Demo

A self-contained Go demo that simulates AI agent scenarios — no external dependencies.

**Terminal 1:**
```bash
export HIVE_JWT_SECRET="demo-secret-do-not-use-in-prod"
go run cmd/gateway/main.go
```

**Terminal 2:**
```bash
go run examples/ai_agent_demo/main.go
```

The demo runs three scenarios:

| Scenario | Command Sent | Result |
|:---------|:-------------|:-------|
| Happy Path | `uptime` | Passes firewall, executes, returns stdout |
| Bash Hallucination | `rm -rf /var/log` | **BLOCKED** — HTTP 403 |
| SQL Injection | `DROP TABLE users CASCADE` | **BLOCKED** — HTTP 403 |

---

## API Reference

### `POST /execute` — Dispatch a command

```
Headers: Authorization: Bearer <JWT>, Content-Type: application/json
Body:    {"agent_id": "my-server", "command": "uptime"}
```

**Success (200):**
```json
{"status": "ok", "stdout": "...", "stderr": "", "exit_code": 0, "agent_id": "my-server"}
```

**Firewall Block (403):**
```json
{"status": "blocked", "error": "Firewall rejected command: ...", "agent_id": "my-server"}
```

**Auth Failure (401):**
```json
{"status": "error", "error": "unauthorized: ..."}
```

### `GET /agents` — List connected agents

```
Headers: Authorization: Bearer <JWT>
```

### `GET /health` — Gateway health (no auth)

Returns agent count, firewall stats, and service status.

### Envelope Routing (Database & API Proxying)

```bash
hive exec -target my-private-server -cmd '{
  "routing": {"protocol": "http", "target": "127.0.0.1:5432"},
  "payload_format": "json",
  "payload": "{\"query\": \"SELECT count(*) FROM orders\"}"
}'
```

---

## Environment Variables

| Variable | Required | Description |
|:---------|:---------|:------------|
| `HIVE_JWT_SECRET` | Yes | HMAC-SHA256 signing key shared between Gateway, CLI, and AI agents |

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for development workflow, commit standards, and architectural guidelines.

Before submitting a PR:
1. `make check` — runs lint, vet, and tests
2. Ensure Go doc comments on all exported identifiers
3. Security-sensitive paths require additional review (see [CODEOWNERS](.github/CODEOWNERS))

---

## Security

For vulnerability reporting, see [SECURITY.md](SECURITY.md). **Do not open a public issue for security bugs** — email `security@zerotrusthive.dev`.

---

## Community

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Changelog](CHANGELOG.md)

---

## License

MIT — see [LICENSE](LICENSE) for details.