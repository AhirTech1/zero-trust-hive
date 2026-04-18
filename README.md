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

**A high-performance, universal deployment and control engine designed for zero-trust edge infrastructure.**

[![Go Version](https://img.shields.io/github/go-mod/go-version/AhirTech1/zero-trust-hive)](https://golang.org/doc/devel/release.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/AhirTech1/zero-trust-hive/actions/workflows/release.yml/badge.svg)](https://github.com/AhirTech1/zero-trust-hive/actions)
[![Release](https://img.shields.io/github/v/release/AhirTech1/zero-trust-hive?include_prereleases)](https://github.com/AhirTech1/zero-trust-hive/releases)

</div>

---

**Zero-Trust Hive** is a modern orchestration system that allows operators to securely manage, introspect, and route traffic to edge devices spanning entirely private networks, NATs, and firewalled environments. By utilizing persistent outbound QUIC tunnels and a semantic API firewall, the Hive fundamentally eliminates the need for open SSH ports, jump hosts, or complex VPN overlays.

## 🧠 Architecture Overview

The system consists of three distinct, heavily optimized Go binaries:

1. **`gateway` (Cloud Control Plane):** The public-facing rendezvous point. It exposes an authenticated API for operators and a secure QUIC listener for incoming edge nodes.
2. **`agent` (Edge Sidecar):** A lightweight daemon deployed inside your locked-down private networks. It dials *out* to the gateway, bypassing inbound firewalls.
3. **`hive` (Operator CLI):** The interactive terminal UI and command engine used to deploy infrastructure and dispatch payloads.

```mermaid
flowchart LR
    classDef operator fill:#2D4A7A,stroke:#ECF0F1,stroke-width:2px,color:#ECF0F1;
    classDef cloud fill:#1B2A4A,stroke:#3498DB,stroke-width:2px,color:#ECF0F1;
    classDef edge fill:#2C3E50,stroke:#27AE60,stroke-width:2px,color:#ECF0F1;
    classDef target fill:#111111,stroke:#E67E22,stroke-width:2px,color:#ECF0F1;

    CLI["hive CLI (Operator)"]:::operator

    subgraph Cloud Gateway
        API["Control API (TCP 8080)"]:::cloud
        FW["Semantic Firewall"]:::cloud
        Router["Zero-Zombie Router"]:::cloud
        QUICGW["QUIC Endpoint (UDP 443)"]:::cloud
    end

    subgraph Disconnected Edge Network
        QUICAgent["Edge Agent"]:::edge
        Sidecar["Sidecar Proxy"]:::edge
        TargetAPP["Local App / DB"]:::target
    end

    CLI -->|"HTTPS + Bearer"| API
    API -->|"Inspect"| FW
    FW -.->|"Validated"| Router
    Router -->|"Dispatch"| QUICGW

    QUICAgent <-->|"mTLS QUIC Tunnel"| QUICGW

    QUICAgent -->|"Decode"| Sidecar
    Sidecar -->|"Local Forwarding"| TargetAPP
````

## 🛡️ Core Capabilities

  * **QUIC NAT Traversal**: Agents dial *out* via UDP `443`. Edge devices require **zero inbound firewall rules** and remain entirely invisible to port scanners (Shodan/Censys).
  * **Ephemeral In-Memory mTLS**: Cryptographic certificates are generated entirely in RAM at boot and rotate automatically. Private keys never touch physical storage.
  * **Semantic API Firewall**: The Gateway HTTP interface actively inspects inbound command payloads. Destructive operations (`rm -rf`, `DROP TABLE`, fork bombs) are blocked at the cloud level before they ever enter the QUIC tunnel.
  * **Universal Sidecar Proxy**: Using the Envelope Routing pattern, operators can securely tunnel raw HTTP/TCP traffic down to isolated microservices running on `localhost` behind the edge firewall.

-----

## 🚀 Installation

Zero-Trust Hive is distributed as statically linked binaries for Linux, macOS, and Windows.

### Method 1: Automated Scripts (Recommended)

Use our streamlined installation scripts. They dynamically detect your operating system and CPU architecture (x86_64 or arm64/M-series) and automatically fetch the latest release artifacts securely from GitHub.

**Linux / macOS:**
```bash
curl -sSfL https://raw.githubusercontent.com/AhirTech1/zero-trust-hive/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
iwr https://raw.githubusercontent.com/AhirTech1/zero-trust-hive/main/install.ps1 -useb | iex
```

### Method 2: Build from Source

Ensure you have [Go 1.22+](https://go.dev/dl/) installed.

```bash
git clone https://github.com/AhirTech1/zero-trust-hive.git
cd zero-trust-hive

# Compile all three binaries
go build -o bin/hive ./cmd/cli
go build -o bin/gateway ./cmd/gateway
go build -o bin/agent ./cmd/agent
```

-----

## 📖 Usage Guide

### 1\. Launch the Cloud Gateway

The Gateway acts as the secure rendezvous point. It must be run on a server with a public IP.

```bash
# Generate a secure token for your CLI to use
export HIVE_API_TOKEN="super_secret_production_token_123"

# Start the gateway (Requires root to bind to port 443)
sudo -E gateway
```

### 2\. Connect an Edge Agent

Deploy the `agent` binary on your target machine (e.g., IoT device, private web server, drone compute module). It will instantly dial out to the Gateway.

```bash
agent -gateway <GATEWAY_PUBLIC_IP>:443 -id production-db-node-01
```

### 3\. Operator CLI Configuration

On your local machine, configure the CLI to authenticate with your Gateway.

```bash
export HIVE_API_TOKEN="super_secret_production_token_123"
export HIVE_GATEWAY_URL="http://<GATEWAY_PUBLIC_IP>:8080"
```

### 4\. Interactive Operations

The `hive` CLI is your command center.

**Deploy New Cloud Infrastructure (Interactive TUI):**

```bash
hive init
```

**List Connected Edge Agents:**

```bash
$ hive list
  ACTIVE AGENTS (1)  
  ────────────────────────────────────────────────────────────
  AGENT ID                     UPTIME             CONNECTED AT
  production-db-node-01        4m12s              2026-04-18T18:22:00Z
```

**Execute Remote Commands:**

```bash
hive exec -target production-db-node-01 -cmd "uptime"
```

-----

## 📦 The Envelope Routing Pattern (Advanced)

Zero-Trust Hive goes beyond simple shell execution. You can proxy raw network traffic to isolated, locally bound services running on the Edge Agent's machine using **JSON Envelopes**.

Instead of a shell command, pass a formatted JSON string to `hive exec`. The Agent's `SidecarAdapter` strips the envelope, wraps the payload, and initiates a local TCP/HTTP connection.

**Use Case: Interrogating an internal diagnostics API that only listens on `localhost:9090`:**

```bash
# 1. Define the Envelope Request
PAYLOAD='{
  "routing": {
    "protocol": "http",
    "target": "127.0.0.1:9090"
  },
  "payload_format": "json",
  "payload": "{\"action\":\"status_dump\"}"
}'

# 2. Dispatch the payload securely down the QUIC tunnel
hive exec -target production-db-node-01 -cmd "$PAYLOAD"
```

The Sidecar proxy executes the local request, absorbs the private HTTP response, and returns the raw bytes up the QUIC tunnel directly back to your CLI terminal.

-----

## 🤝 Contributing

We welcome contributions to the Zero-Trust Hive engine! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on how to submit pull requests, report bugs, and suggest new features.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.