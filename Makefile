.PHONY: all build test lint vet clean

BIN_DIR := bin
GOBUILD := go build
GOTEST := go test
GOLINT := golangci-lint run

# Build all three binaries
all: build

build:
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -o $(BIN_DIR)/hive    ./cmd/cli
	$(GOBUILD) -o $(BIN_DIR)/gateway ./cmd/gateway
	$(GOBUILD) -o $(BIN_DIR)/agent   ./cmd/agent

# Build with version injection (set VERSION env var)
build-release:
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -ldflags "-s -w -X github.com/AhirTech1/zero-trust-hive/internal/tui.Version=$(VERSION)" -o $(BIN_DIR)/hive    ./cmd/cli
	$(GOBUILD) -ldflags "-s -w" -o $(BIN_DIR)/gateway ./cmd/gateway
	$(GOBUILD) -ldflags "-s -w" -o $(BIN_DIR)/agent   ./cmd/agent

# Run all tests with race detection
test:
	$(GOTEST) -race -count=1 ./...

# Run tests with coverage
cover:
	$(GOTEST) -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out

# Run linter
lint:
	$(GOLINT) ./...

# Go vet
vet:
	go vet ./...

# Format code
fmt:
	go fmt ./...
	goimports -w -local github.com/AhirTech1/zero-trust-hive .

# Full CI check — lint, vet, test
check: lint vet test

# Clean build artifacts
clean:
	rm -rf $(BIN_DIR)
	rm -f coverage.out

# Start development gateway (for local testing)
dev-gateway:
	@export HIVE_JWT_SECRET="dev-secret-do-not-use-in-prod"
	go run ./cmd/gateway

# Run AI agent demo (requires gateway running in another terminal)
demo:
	go run ./examples/ai_agent_demo