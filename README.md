<div align="center">

```text
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
```

**Universal Zero-Trust Deployment Engine**

[![Go Version](https://img.shields.io/github/go-mod/go-version/zero-trust-hive/hive)](https://golang.org/doc/devel/release.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/zero-trust-hive/hive/actions/workflows/release.yml/badge.svg)](https://github.com/zero-trust-hive/hive/actions)
[![Release](https://img.shields.io/github/v/release/zero-trust-hive/hive?include_prereleases)](https://github.com/zero-trust-hive/hive/releases)

</div>

---

**Zero-Trust Hive** is a highly secure, high-performance orchestration and remote control system. Designed for enterprise infrastructures, it completely bypasses the need for traditional SSH, inbound firewall ports, and complex VPNs.

The system is composed of three interconnected Go binaries:
1. **hive (The Operator CLI)**: Your control center. Features a beautiful Terminal UI for deploying AWS infrastructure, listing connected edge agents, and dispatching execution payloads.
2. **gateway (The Cloud Gateway)**: The command nexus. It runs an authenticated HTTP Control API and a secure QUIC listener that edge devices dial into. Includes a strict **Semantic Firewall** that automatically blocks destructive strings like `rm -rf` and SQL `DROP/DELETE` statements.
3. **agent (The Edge Agent)**: A lightweight daemon that runs on your downstream servers or edge devices. It strictly dials *out* to the Cloud Gateway via UDP 443 (QUIC) and executes authorized commands or proxies HTTP/TCP traffic via its sidecar adapter.

## Key Features

* **Reverse QUIC Tunnels**: Edge agents initiate connections out to the Cloud Gateway. No inbound ports need to be opened on your private servers. Scanners cannot see them.
* **Ephemeral In-Memory Cryptography**: mTLS keys are dynamically generated entirely in RAM and rotate constantly. Nothing touches disk, nullifying local credential extraction payloads.
* **Interactive AWS Deployment**: Execute `hive init` to launch a stunning Charm-bracelet `huh` powered Terminal UI that automatically detects your `~/.aws/credentials`, dynamic regions, and AMI machine images to deploy your infrastructure safely.
* **Semantic Code Firewall**: An intelligent pre-flight check layer that intercepts and blocks known destructive command patterns downstream before they are even sent to the agent.
* **Envelope Routing Proxy**: The agent handles JSON Envelopes, acting as a secure TCP/HTTP proxy to connect you directly to segmented, local-only microservices running inside the secure network layer.

## Architectural Flow

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

---

## Quick Start Guide

### 1. Launch the Cloud Gateway
Run the central nexus on a publicly accessible server (acting as the meeting point).
```bash
sudo gateway
# Listens on UDP 443 (QUIC) and TCP 8080 (Control API)
```

### 2. Connect Edge Agents
Run the agent on your target devices. They will magically dial out into the Gateway and register.
```bash
agent -gateway <GATEWAY_IP>:443 -id webserver-prod-01
```

### 3. Control via the CLI
Use the unified `hive` tool to issue commands globally. Ensure the Gateway API token is exported first.
```bash
export HIVE_API_TOKEN="your_secure_bearer_token"
```

**Discover & Deploy Infrastructure:**
```bash
hive init
```

**List Connected Agents:**
```bash
hive list
```

**Execute Commands Remotely:**
```bash
hive exec -target webserver-prod-01 -cmd "uptime"
```

**Proxy Local Traffic (Sidecar Envelope Pattern):**
```bash
hive exec -target webserver-prod-01 -cmd '{
  "routing": {"protocol": "http", "target": "127.0.0.1:9090"},
  "payload_format": "json",
  "payload": "{\"status\":\"query\"}"
}'
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
