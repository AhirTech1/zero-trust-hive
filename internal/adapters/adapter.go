// ─────────────────────────────────────────────────────────────────────────────
// Package adapters — Universal Adapter Interface
// ─────────────────────────────────────────────────────────────────────────────
// The Edge Agent does NOT hardcode command execution logic in main.go.
// Instead, all execution flows through the EdgeAdapter interface. This
// decouples the QUIC transport layer from the execution layer, allowing
// different adapter implementations to be swapped in without modifying
// the agent core.
//
// The interface contract is simple:
//   - Receive an opaque payload (the command from the Gateway)
//   - Execute the intent
//   - Return the result as bytes (or an error)
//
// Built-in adapters:
//   - SystemAdapter (system.go): Executes safe OS commands via os/exec
//
// Future adapters could include:
//   - ContainerAdapter: Execute commands inside Docker/Podman containers
//   - K8sAdapter: Apply manifests to a Kubernetes cluster
//   - TerraformAdapter: Run terraform plan/apply
//
// ─────────────────────────────────────────────────────────────────────────────
package adapters

// ─────────────────────────────────────────────────────────────────────────────
// EdgeAdapter — the universal execution interface
// ─────────────────────────────────────────────────────────────────────────────
// Every adapter that the Edge Agent can use must implement this interface.
// The agent's command loop calls ExecuteIntent for every command received
// from the Gateway, and writes the returned bytes back to the QUIC stream
// as the response.
//
// Design Rationale:
//   - []byte input allows structured (JSON) or raw (text) payloads
//   - []byte output allows structured (JSON) or raw (stdout) responses
//   - error signals execution failures separately from command output
//   - This minimal surface makes adapters trivial to implement and test
// ─────────────────────────────────────────────────────────────────────────────

// EdgeAdapter defines the contract for all execution backends that the
// Edge Agent can delegate commands to. Implementations must be safe to
// call concurrently from multiple goroutines (one per incoming QUIC stream).
type EdgeAdapter interface {
	// ExecuteIntent processes a command payload received from the Gateway.
	//
	// Parameters:
	//   payload — the raw command bytes from the QUIC stream. The adapter
	//             is responsible for parsing/interpreting the format.
	//
	// Returns:
	//   []byte — the execution result to send back to the Gateway
	//   error  — non-nil if execution failed (the error message is sent
	//            back to the Gateway as the response)
	ExecuteIntent(payload []byte) ([]byte, error)

	// Name returns a human-readable identifier for this adapter.
	// Used in logging and status reporting.
	Name() string
}
