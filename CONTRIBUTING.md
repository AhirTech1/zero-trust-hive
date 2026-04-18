# Contributing to Zero-Trust Hive

First off, thank you for considering contributing to Zero-Trust Hive. It's people like you that make open-source software such a great and reliable ecosystem.

## Engineering Philosophy

Zero-Trust Hive is built to Fortune-500 standards. Our code must remain concise, highly concurrent, and fundamentally defensive. 

1. **Defensive by Design**: Any new feature exposed to the network must have strict timeouts and context cancellations attached.
2. **Minimal Dependencies**: We rely heavily on the Go standard library. Avoid pulling in third-party libraries for trivial operations. 
3. **No Magic**: Constants should be declared at the top of packages. Side-effects should be minimized and documented explicitly.

## Development Workflow

### 1. Prerequisites
- **Go 1.22+**
- **golangci-lint** (`go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest`)
- **git**

### 2. Commit Standards
We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification.
Valid prefixes include:
- `feat:` (New feature)
- `fix:` (Bug fix)
- `docs:` (Documentation changes)
- `refactor:` (Code restructuring)
- `perf:` (Performance optimization)
- `test:` (Adding/fixing tests)

*Example:* `feat(agent): implement Kubernetes manifest sidecar adapter`

### 3. Pull Request Process
1. Fork the repo and create your branch from `main`.
2. Ensure your code passes all lint checks: `golangci-lint run ./...`
3. Ensure the project builds cleanly: `go build ./... && go vet ./...`
4. Submit your PR. A maintainer will execute a security audit on your implementation before merging.

## Architectural Guidelines

If you are modifying native QUIC state machines (e.g., `internal/network/quic.go`):
- Ensure that `stream.Close()` is used over `stream.CancelWrite(0)` to guarantee clean FIN packets.
- Ensure that you are not introducing blocking channel reads inside the main stream-acceptance loop without a context boundary.

If you are expanding the TUI (`internal/tui/`):
- Rely exclusively on the defined lipgloss tokens (`ColorNavy`, `ColorAccentBlue`, etc.). Do not introduce raw hex codes inside individual views.

Thank you for helping us build a more secure deployment paradigm!
