# Security Policy

## Supported Versions

Security patches are backported to the last two minor releases.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Do not open a public issue.** Email `security@zerotrusthive.dev` with a detailed description and reproduction steps. You will receive a response within 48 hours with an assessment and expected timeline.

### What to Include

- Affected component (gateway, agent, CLI, or protocol)
- Steps to reproduce
- Potential impact
- Any suggested mitigations

### Disclosure Timeline

1. Report received → acknowledged within 48 hours
2. Fix developed and reviewed → typically 72 hours
3. Patch released → coordinated disclosure
4. CVE requested if applicable

## Security Model

Zero-Trust Hive's threat model assumes:
- The Gateway runs on a trusted cloud server
- The Edge Agent runs on a trusted private machine
- The network path between them is untrusted
- AI agents may hallucinate and generate destructive commands

### Cryptographic Guarantees

- **JWT Authentication**: HMAC-SHA256 with scoped claims and 24-hour expiry
- **Transport Security**: QUIC with TLS 1.3, ephemeral RSA-2048 certificates rotated hourly
- **Key Material**: Private keys never touch disk — generated and held entirely in memory
- **Forward Secrecy**: Hourly certificate rotation limits exposure window

### Known Limitations

- Self-signed certificates require `InsecureSkipVerify` on the agent side. In production deployments, integrate with a proper PKI or pin the Gateway's CA certificate.
- The Semantic Firewall uses regex inspection — it is a defense-in-depth layer, not a formal verifier. Pair it with the SystemAdapter allowlist for defense in depth.

## Responsible Disclosure Hall of Fame

We gratefully acknowledge security researchers who have responsibly disclosed vulnerabilities. Names and findings are listed here with permission.