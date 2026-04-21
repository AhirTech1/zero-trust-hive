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

**`ngrok` for AI Agents — A secure, zero-trust execution tunnel that lets cloud AI agents safely operate on your private infrastructure.**

[![Go Version](https://img.shields.io/github/go-mod/go-version/AhirTech1/zero-trust-hive)](https://golang.org/doc/devel/release.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/AhirTech1/zero-trust-hive/actions/workflows/release.yml/badge.svg)](https://github.com/AhirTech1/zero-trust-hive/actions)
[![Release](https://img.shields.io/github/v/release/AhirTech1/zero-trust-hive?include_prereleases)](https://github.com/AhirTech1/zero-trust-hive/releases)

</div>

---

## The Problem

AI agents built with LangChain, AutoGPT, CrewAI, or Claude Computer Use live in the cloud. But the data they need to act on — databases, filesystems, internal APIs — lives on **your** private machines, behind firewalls, NATs, and air-gapped networks.

Today, connecting them requires punching holes in your firewall, exposing SSH ports, or maintaining fragile VPN tunnels. **Every open port is an attack surface.** And worse — LLMs hallucinate. A single hallucinated `rm -rf /` or `DROP TABLE users` can destroy your production environment.

## The Solution

**Zero-Trust Hive** creates a persistent, reverse QUIC tunnel from your private machine *out* to a cloud gateway. Your AI agent authenticates with a **signed JWT**, sends execution requests to the gateway's HTTP API, and a **Semantic Firewall** inspects every command *before* it enters the tunnel — automatically blocking hallucinated destructive operations. Only validated, safe instructions reach your machine.

**No inbound ports. No SSH. No VPN. No exposed attack surface.**

---

## 🧠 Architecture

```mermaid
flowchart LR
    classDef agent fill:#6C3483,stroke:#ECF0F1,stroke-width:2px,color:#ECF0F1;
    classDef cloud fill:#1B2A4A,stroke:#3498DB,stroke-width:2px,color:#ECF0F1;
    classDef firewall fill:#922B21,stroke:#E74C3C,stroke-width:2px,color:#ECF0F1;
    classDef edge fill:#2C3E50,stroke:#27AE60,stroke-width:2px,color:#ECF0F1;
    classDef target fill:#111111,stroke:#E67E22,stroke-width:2px,color:#ECF0F1;

    AI["☁️ Cloud AI Agent<br/>(LangChain / AutoGPT / Claude)"]:::agent

    subgraph Gateway ["Zero-Trust Hive Gateway (Cloud Server)"]
        JWT["JWT Auth<br/>(HMAC-SHA256)"]:::cloud
        FW["Semantic Firewall<br/>(15 Regex Rules)"]:::firewall
        API["Control API<br/>(TCP 8080)"]:::cloud
        QUICGW["QUIC Endpoint<br/>(UDP 443)"]:::cloud
    end

    subgraph Private ["Your Private Network (Zero Inbound Ports)"]
        EdgeAgent["Hive Edge Agent"]:::edge
        Sidecar["Sidecar Proxy"]:::edge
        DB["Private DB / API / FS"]:::target
    end

    AI -->|"POST /execute + JWT"| JWT
    JWT -->|"Claims Validated"| API
    API -->|"Inspect Command"| FW
    FW -.->|"✅ Safe → Forward"| QUICGW
    FW -.->|"🛡 Blocked → HTTP 403"| AI

    EdgeAgent <-->|"Encrypted mTLS QUIC Tunnel<br/>(Ephemeral Certs, Hourly Rotation)"| QUICGW

    EdgeAgent -->|"Execute / Proxy"| Sidecar
    Sidecar -->|"localhost Only"| DB
```

The system ships as three purpose-built Go binaries:

| Binary | Role | Where It Runs |
|:-------|:-----|:--------------|
| **`gateway`** | JWT-authenticated API → Semantic Firewall → QUIC listener | Your cloud server (public IP) |
| **`agent`** | Reverse tunnel anchor → local execution & sidecar proxy | Your private machine (no inbound ports) |
| **`hive`** | Operator CLI for bootstrapping, fleet monitoring, and dispatch | Your laptop / CI pipeline |

---

## 🛡️ Security Architecture

Zero-Trust Hive enforces **three layers of security** on every request before a command reaches your private machine:

### Layer 1: JWT Authentication (HMAC-SHA256)

Every API request must carry a signed JWT in the `Authorization: Bearer <token>` header. The Gateway validates the signature against a shared `HIVE_JWT_SECRET`, then extracts the claims (`sub`, `scope`, `exp`) for audit logging. Static API tokens are gone — tokens are cryptographically signed, scoped (`execute`, `read`, `admin`), and expire after 24 hours.

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
                      └── sub: "langchain-agent"
                      └── scope: "execute"  
                      └── exp: 1713628800
```

### Layer 2: Semantic Firewall (AI Hallucination Guard)

The Semantic Firewall is a struct-based inspection engine with **15 compiled regular expressions** that intercept destructive commands at the Gateway — before they ever enter the QUIC tunnel. It blocks:

| Category | Blocked Patterns | Severity |
|:---------|:-----------------|:---------|
| **Recursive Deletions** | `rm -rf`, `rm -f /*`, `--no-preserve-root` | 🔴 Critical |
| **Database Drops** | `DROP TABLE`, `DROP DATABASE`, `TRUNCATE`, `DELETE FROM` | 🔴 Critical |
| **Filesystem Formatters** | `mkfs`, `fdisk`, `dd if=` | 🔴 Critical |
| **Fork Bombs** | `:(){ :\|:& };:` | 🔴 Critical |
| **Block Device Writes** | `> /dev/sda`, `> /dev/hda` | 🔴 Critical |
| **Privilege Escalation** | `GRANT ALL`, `REVOKE`, `ALTER TABLE` | 🟠 High |
| **System Control** | `shutdown`, `reboot`, `init 0` | 🟠 High |
| **Credential Exfiltration** | `PASSWORD`, `PASSWORDS` | 🟠 High |
| **Permission Manipulation** | `chmod 777 /`, `chmod -R` on root paths | 🟠 High |

When a command is blocked, the API immediately returns an **HTTP 403** with AI-parsable JSON:

```json
{
  "status": "blocked",
  "error": "Firewall rejected command: BLOCKED [Bash]: rm with recursive/force flags — matched: \"rm -rf\"",
  "agent_id": "production-server-01"
}
```

The firewall also tracks live statistics (total inspected, total blocked, rules loaded) exposed via `GET /health`.

### Layer 3: Ephemeral In-Memory Cryptography

All mTLS certificates are RSA 2048, generated entirely in RAM at boot, and rotate hourly via a background goroutine. Private keys **never touch disk**, eliminating credential theft from compromised filesystems. The QUIC tunnel enforces TLS 1.3 minimum with `h3` / `hive-quic` ALPN negotiation.

### Bonus: Zero-Inbound Architecture

The Edge Agent initiates an *outbound-only* QUIC connection over UDP 443. Your private machine opens **zero listening ports**. It is invisible to Shodan, Censys, and any external port scanner. There is no attack surface to exploit.

---

## 🚀 Installation

### Automated Install (Recommended)

**Linux / macOS:**
```bash
curl -sSfL https://raw.githubusercontent.com/AhirTech1/zero-trust-hive/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
iwr https://raw.githubusercontent.com/AhirTech1/zero-trust-hive/main/install.ps1 -useb | iex
```

### Build from Source

Requires [Go 1.22+](https://go.dev/dl/).

```bash
git clone https://github.com/AhirTech1/zero-trust-hive.git
cd zero-trust-hive

go build -o bin/hive    ./cmd/cli
go build -o bin/gateway ./cmd/gateway
go build -o bin/agent   ./cmd/agent
```

---

## ⚡ Quick Start

### 1. Bootstrap Configuration

```bash
./bin/hive init
```

This generates a `.env` file containing:
- `HIVE_JWT_SECRET` — a cryptographically random 64-character HMAC signing key
- `HIVE_BOOTSTRAP_TOKEN` — a pre-signed admin JWT valid for 24 hours

### 2. Start the Gateway (Cloud Server)

```bash
export HIVE_JWT_SECRET="<your_secret_from_.env>"
sudo -E ./bin/gateway
# ✓ QUIC Ghost Endpoint .... UDP 0.0.0.0:443
# ✓ HTTP Control API ....... TCP 0.0.0.0:8080
# ✓ Semantic Firewall ...... Active (15 rules)
# ✓ JWT Authentication ..... Active (HMAC-SHA256)
```

### 3. Connect an Edge Agent (Private Machine)

```bash
./bin/agent -gateway <GATEWAY_IP>:443 -id my-private-server
# The agent dials OUT — no firewall changes needed.
```

### 4. Execute Commands

**From the CLI:**
```bash
export HIVE_JWT_SECRET="<your_secret>"

# List all connected agents
hive list

# Execute a safe command
hive exec -target my-private-server -cmd "uptime"

# Read the full operator manual
hive help
```

**From your AI Agent (any language — it's just HTTP):**
```go
POST http://<GATEWAY_IP>:8080/execute
Authorization: Bearer <signed_jwt>
Content-Type: application/json

{"agent_id": "my-private-server", "command": "cat /var/log/app/errors.log | tail -50"}
```

**Structured JSON Response:**
```json
{
  "status": "ok",
  "stdout": " 14:22:01 up 3 days, 4:12, 2 users, load average: 0.15, 0.10, 0.05",
  "stderr": "",
  "exit_code": 0,
  "agent_id": "my-private-server"
}
```

---

## 🧪 Try the Demo (Two Terminals, 30 Seconds)

The repository includes a self-contained Go demo that simulates an AI agent communicating with the Gateway. It demonstrates both the **Happy Path** and the **Blocked Hallucination Path** — no external dependencies required.

**Terminal 1 — Start the Gateway:**
```bash
export HIVE_JWT_SECRET="demo-secret-do-not-use-in-prod"
go run cmd/gateway/main.go
```

**Terminal 2 — Run the AI Agent Demo:**
```bash
go run examples/ai_agent_demo/main.go
```

The demo automatically runs three scenarios:

| Scenario | Command Sent | Result |
|:---------|:-------------|:-------|
| ✅ Happy Path | `uptime` | Passes firewall → executes on agent → returns `stdout` |
| 🛡 Bash Hallucination | `rm -rf /var/log` | **BLOCKED** — HTTP 403, private machine untouched |
| 🛡 SQL Injection | `DROP TABLE users CASCADE` | **BLOCKED** — HTTP 403, database safe |

The demo generates JWTs, formats colored terminal output, and pretty-prints the Gateway's structured JSON responses so you can experience the security model firsthand.

---

## 📦 Envelope Routing (Database & API Proxying)

Beyond shell commands, the Edge Agent's Sidecar Proxy can forward structured HTTP/TCP traffic to local-only services using JSON **Envelope Routing**. Your AI agent can query a private PostgreSQL instance or hit an internal REST API on `localhost:9090` — securely, through the encrypted tunnel.

```bash
hive exec -target my-private-server -cmd '{
  "routing": {
    "protocol": "http",
    "target": "127.0.0.1:5432"
  },
  "payload_format": "json",
  "payload": "{\"query\": \"SELECT count(*) FROM orders WHERE status = '\''pending'\''\"}"
}'
```

The Sidecar opens a local connection, sends the payload, collects the response, and returns it through the QUIC tunnel — all without the private service ever being exposed to the internet.

---

## 🔧 Environment Variables

| Variable | Required | Description |
|:---------|:---------|:------------|
| `HIVE_JWT_SECRET` | **Yes** | HMAC-SHA256 signing key for JWT authentication. Shared between Gateway, CLI, and AI agents. Generated by `hive init`. |

---

## 📐 API Reference

### `POST /execute` — Dispatch a command to an Edge Agent

**Headers:** `Authorization: Bearer <JWT>`, `Content-Type: application/json`

**Request Body:**
```json
{"agent_id": "my-server", "command": "uptime"}
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
{"status": "error", "error": "unauthorized: token validation failed: ..."}
```

### `GET /agents` — List connected Edge Agents
**Headers:** `Authorization: Bearer <JWT>`

### `GET /health` — Gateway health check (no auth)
Returns agent count, firewall stats, and service status.

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on submitting pull requests and reporting bugs.

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.