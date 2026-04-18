<div align="center">
_____                   ______                 __    __  ___          
 /__  / ___  _________   /_  __/______  _______/ /_  / / / (_)   _____
   / / / _ \/ ___/ __ \   / / / ___/ / / / ___/ __/ / /_/ / / | / / _ \
  / /_/  __/ /  / /_/ /  / / / /  / /_/ (__  ) /_  / __  / /| |/ /  __/
 /____\___/_/   \____/  /_/ /_/   \__,_/____/\__/ /_/ /_/_/ |___/\___/
# Zero-Trust Hive

**A high-performance, universal deployment and control engine designed for zero-trust edge infrastructure.**

[![Go Version](https://img.shields.io/github/go-mod/go-version/zero-trust-hive/hive)](https://golang.org/doc/devel/release.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/zero-trust-hive/hive/actions/workflows/release.yml/badge.svg)](https://github.com/zero-trust-hive/hive/actions)
[![Release](https://img.shields.io/github/v/release/zero-trust-hive/hive?include_prereleases)](https://github.com/zero-trust-hive/hive/releases)

</div>

---

Zero-Trust Hive is a modern orchestration system that allows operators to securely manage, introspect, and route traffic to edge devices spanning entirely private networks, NATs, and firewalled environments. By utilizing persistent outbound QUIC tunnels and a semantic API firewall, the Hive fundamentally eliminates the need for open SSH ports, jump hosts, or complex VPN overlays.

## Architecture Overview

The system consists of three native binaries: the Operator CLI (`hive`), the Cloud Gateway (`gateway`), and the universal Edge Agent (`agent`).

```mermaid
flowchart LR
    classDef operator fill:#2D4A7A,stroke:#ECF0F1,stroke-width:2px,color:#ECF0F1;
    classDef cloud fill:#1B2A4A,stroke:#3498DB,stroke-width:2px,color:#ECF0F1;
    classDef edge fill:#2C3E50,stroke:#27AE60,stroke-width:2px,color:#ECF0F1;
    classDef tunnel fill:none,stroke:#5DADE2,stroke-width:3px,stroke-dasharray: 5 5;

    subgraph Operator Plane
        CLI["hive CLI (Operator)"]:::operator
    end

    subgraph Cloud Gateway (Public)
        API["Control API (:8080)"]:::cloud
        FW["Semantic Firewall"]:::cloud
        Router["Zero-Zombie Router"]:::cloud
        QUICGW["QUIC Endpoint (:443)"]:::cloud
    end

    subgraph Disconnected Edge (Private NAT)
        QUICAgent["QUIC Anchor"]:::edge
        Sidecar["Sidecar Adapter"]:::edge
        Target["Internal Service"]:::edge
    end

    %% Flow
    CLI -- "HTTPS Bearer Auth" --> API
    API --> FW
    FW -. "Validated Instruction" .-> Router
    Router --> QUICGW

    QUICAgent <== "mTLS Tunnel (Persistent)" ===> QUICGW

    QUICAgent --> Sidecar
    Sidecar -- "Local HTTP/TCP" --> Target
```

## Core Capabilities

* **QUIC NAT Traversal**: Agents dial *out* via UDP `443` to the Cloud Gateway, keeping the connection multiplexed and alive. Edge devices require exactly zero ingress firewall rules and are entirely invisible to port scanners.
* **In-Memory Ephemeral mTLS**: Cryptographic material is generated completely in RAM at boot and rotates periodically. Certificates never touch physical storage, nullifying local credential extraction vectors.
* **Semantic API Firewall**: The Gateway HTTP interface actively inspects inbound JSON payloads for destructive operations (e.g., `rm -rf`, `DROP TABLE`). It drops malformed or malicious commands before they ever enter the QUIC tunnel.
* **Universal Sidecar Proxy**: The Edge Agent is completely abstracted. Via the Envelope Routing pattern, operators can securely tunnel HTTP/JSON traffic down to private microservices running exclusively on localhost behind the edge firewall.

---

## Installation

Zero-Trust Hive is distributed as stripped, statically linked Go binaries.

**Via Shell Script:**
```bash
curl -sSfL https://raw.githubusercontent.com/zero-trust-hive/hive/main/install.sh | sh
```

**Via GoReleaser (Manual):**
Download the latest pre-compiled archive for Linux, macOS, or Windows directly from the [GitHub Releases](https://github.com/zero-trust-hive/hive/releases) page.

---

## Usage Guide

The unified `hive` CLI acts as your primary control plane.

### 1. Launch the Cloud Gateway
The Gateway acts as the secure rendezvous point. It exposes UDP `443` for agents and TCP `8080` for the Control API.
```bash
# Gateway must be reachable by Edge Agents
sudo gateway
```

### 2. Connect an Edge Agent
Deploy the lightweight agent binary on any target machine (IoT device, Kubernetes pod, bare-metal server).
```bash
agent -gateway 203.0.113.50:443 -id webserver-prod-01
```

### 3. Operator CLI configuration
Export your bearer token to authenticate your CLI commands:
```bash
export HIVE_API_TOKEN="your_secure_bearer_token"
```

### 4. Interactive Deployment (Phase 1 Infrastructure)
For deploying AWS infrastructure interactively via the built-in TUI:
```bash
hive init
```

### 5. Fleet Monitoring
List all active Edge Agents currently holding an active QUIC connection to the Gateway:
```bash
$ hive list
  ACTIVE AGENTS (1)  
  ────────────────────────────────────────────────────────────
  AGENT ID               UPTIME             CONNECTED AT
  webserver-prod-01      4m12s              2026-04-18T18:22:00Z
```

---

## The Envelope Routing Pattern

Zero-Trust Hive goes beyond simple shell execution. You can proxy raw network traffic to isolated, locally bound services running on the Edge Agent's machine using **JSON Envelopes**. 

Instead of passing a shell command like `uptime`, pass a formatted JSON string to `hive exec`. The Agent's `SidecarAdapter` strips the envelope, wraps the payload, and initiates a local TCP/HTTP connection.

**Example: Interrogating an internal diagnostics API:**

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

# 2. Dispatch via the CLI
hive exec -target webserver-prod-01 -cmd "$PAYLOAD"
```

The Sidecar proxy executes the local request, absorbs the private HTTP response, and returns the raw bytes up the QUIC tunnel directly back to your CLI.

---

## Security Reporting

If you have discovered a vulnerability in the Zero-Trust Hive architecture, please refer to the [Security Policy](SECURITY.md) for disclosure guidelines. Do not file public issues for security vulnerabilities.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
