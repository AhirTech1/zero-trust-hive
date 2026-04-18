// ─────────────────────────────────────────────────────────────────────────────
// Package network — HTTP Control API
// ─────────────────────────────────────────────────────────────────────────────
// Exposes an HTTP POST endpoint on TCP 0.0.0.0:8080 for operators to dispatch
// commands to connected Edge Agents via the QUIC routing table.
//
// Security Layers:
//  1. Bearer Token Authentication — every request must carry a valid token
//  2. Semantic Firewall — payloads are inspected for destructive patterns
//  3. 5-Second Timeout — prevents deadlocks if an agent hangs
//
// Endpoint:
//
//	POST /execute
//	Headers:  Authorization: Bearer <TOKEN>
//	Body:     {"agent_id": "...", "command": "..."}
//	Response: {"status": "...", "output": "..."} or {"error": "..."}
//
// ─────────────────────────────────────────────────────────────────────────────
package network

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	// apiListenAddr — the TCP address the HTTP control API binds to.
	apiListenAddr = "0.0.0.0:8080"

	// commandTimeout — maximum time to wait for an agent to respond to a
	// command. If the agent doesn't respond within this window, the request
	// fails with a timeout error. This prevents the API from deadlocking
	// on hung agents.
	commandTimeout = 5 * time.Second

	// maxRequestBody — maximum size of the JSON request body (1 MiB).
	// Prevents memory exhaustion from oversized payloads.
	maxRequestBody = 1 << 20 // 1 MiB
)

// ─────────────────────────────────────────────────────────────────────────────
// Request / Response types
// ─────────────────────────────────────────────────────────────────────────────

// ExecuteRequest is the JSON body for POST /execute.
type ExecuteRequest struct {
	// AgentID identifies the target Edge Agent in the routing table.
	AgentID string `json:"agent_id"`

	// Command is the instruction to send to the agent.
	Command string `json:"command"`
}

// ExecuteResponse is the JSON response from POST /execute.
type ExecuteResponse struct {
	// Status is "ok" on success, "error" on failure.
	Status string `json:"status"`

	// Output contains the agent's response (on success).
	Output string `json:"output,omitempty"`

	// Error contains the error message (on failure).
	Error string `json:"error,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// ControlAPI — the HTTP server struct
// ─────────────────────────────────────────────────────────────────────────────

// ControlAPI serves the HTTP control endpoint for dispatching commands to
// Edge Agents through the QUIC routing table.
type ControlAPI struct {
	// router is the agent routing table for looking up connections.
	router *Router

	// bearerToken is the expected token for Bearer authentication.
	// In production, this would come from a secrets manager or env var.
	bearerToken string

	// server is the underlying HTTP server (for graceful shutdown).
	server *http.Server
}

// ─────────────────────────────────────────────────────────────────────────────
// NewControlAPI — constructor
// ─────────────────────────────────────────────────────────────────────────────

func NewControlAPI(router *Router, bearerToken string) *ControlAPI {
	api := &ControlAPI{
		router:      router,
		bearerToken: bearerToken,
	}

	// ── Set up the HTTP mux ────────────────────────────────────────────
	mux := http.NewServeMux()
	mux.HandleFunc("POST /execute", api.handleExecute)
	mux.HandleFunc("GET /agents", api.handleAgents)

	// Health check endpoint — useful for load balancers and monitoring.
	mux.HandleFunc("GET /health", api.handleHealth)

	api.server = &http.Server{
		Addr:         apiListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return api
}

// ─────────────────────────────────────────────────────────────────────────────
// Start — begins serving the HTTP control API
// ─────────────────────────────────────────────────────────────────────────────

func (api *ControlAPI) Start() error {
	log.Printf("[API] ✓ Control API listening on %s (TCP/HTTP)", apiListenAddr)
	log.Printf("[API]   POST /execute — dispatch commands to agents")
	log.Printf("[API]   GET  /health  — gateway health check")

	// ListenAndServe blocks until the server is shut down.
	if err := api.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("control API failed: %w", err)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Shutdown — gracefully stops the HTTP server
// ─────────────────────────────────────────────────────────────────────────────

func (api *ControlAPI) Shutdown(ctx context.Context) error {
	log.Printf("[API] Shutting down control API...")
	return api.server.Shutdown(ctx)
}

// ─────────────────────────────────────────────────────────────────────────────
// handleHealth — GET /health
// ─────────────────────────────────────────────────────────────────────────────
// Returns the gateway's health status and active agent count.
// ─────────────────────────────────────────────────────────────────────────────

func (api *ControlAPI) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "healthy",
		"active_agents": api.router.Count(),
		"agents":        api.router.List(),
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// handleAgents — GET /agents
// ─────────────────────────────────────────────────────────────────────────────
// Returns a detailed JSON array of connected agents and their uptimes.
// Requires Bearer authentication.
// ─────────────────────────────────────────────────────────────────────────────

func (api *ControlAPI) handleAgents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if err := api.authenticateRequest(r); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ExecuteResponse{
			Status: "error",
			Error:  "unauthorized: invalid or missing Bearer token",
		})
		return
	}

	agents := api.router.ListAgents()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"count":  len(agents),
		"agents": agents,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// handleExecute — POST /execute
// ─────────────────────────────────────────────────────────────────────────────
// The main command dispatch endpoint. Enforces three security layers:
//   1. Bearer Token Authentication
//   2. Semantic Firewall Inspection
//   3. 5-Second Agent Communication Timeout
// ─────────────────────────────────────────────────────────────────────────────

func (api *ControlAPI) handleExecute(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// ── Layer 1: Bearer Token Authentication ───────────────────────────
	// The Authorization header must contain "Bearer <TOKEN>" where <TOKEN>
	// matches the configured bearer token exactly.
	if err := api.authenticateRequest(r); err != nil {
		log.Printf("[API] ✗ Auth failed from %s: %v", r.RemoteAddr, err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ExecuteResponse{
			Status: "error",
			Error:  "unauthorized: invalid or missing Bearer token",
		})
		return
	}

	// ── Parse the request body ─────────────────────────────────────────
	body := http.MaxBytesReader(w, r.Body, maxRequestBody)
	defer body.Close()

	var req ExecuteRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ExecuteResponse{
			Status: "error",
			Error:  fmt.Sprintf("invalid JSON body: %v", err),
		})
		return
	}

	// Validate required fields.
	if req.AgentID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ExecuteResponse{
			Status: "error",
			Error:  "agent_id is required",
		})
		return
	}
	if req.Command == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ExecuteResponse{
			Status: "error",
			Error:  "command is required",
		})
		return
	}

	// ── Layer 2: Semantic Firewall ─────────────────────────────────────
	// Inspect the command payload for destructive SQL/Bash patterns.
	if err := InspectPayload(req.Command); err != nil {
		log.Printf("[API] 🛡 Firewall blocked command to agent %q: %v", req.AgentID, err)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ExecuteResponse{
			Status: "error",
			Error:  fmt.Sprintf("command blocked by semantic firewall: %v", err),
		})
		return
	}

	// ── Layer 3: Dispatch to Agent with 5s Timeout ─────────────────────
	// Look up the agent in the routing table.
	conn, err := api.router.Get(req.AgentID)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ExecuteResponse{
			Status: "error",
			Error:  fmt.Sprintf("agent not found: %v", err),
		})
		return
	}

	// Create a timeout context — if the agent doesn't respond within 5
	// seconds, we abort to prevent the API from deadlocking.
	timeoutCtx, cancel := context.WithTimeout(r.Context(), commandTimeout)
	defer cancel()

	// Open a new QUIC stream to the agent for this command.
	stream, err := conn.OpenStreamSync(timeoutCtx)
	if err != nil {
		log.Printf("[API] ⚠ Failed to open stream to agent %q: %v", req.AgentID, err)
		w.WriteHeader(http.StatusGatewayTimeout)
		json.NewEncoder(w).Encode(ExecuteResponse{
			Status: "error",
			Error:  fmt.Sprintf("failed to reach agent (timeout: %v): %v", commandTimeout, err),
		})
		return
	}

	// ── Send the command to the agent ──────────────────────────────────
	if _, err := stream.Write([]byte(req.Command)); err != nil {
		log.Printf("[API] ⚠ Failed to write command to agent %q: %v", req.AgentID, err)
		stream.Close()
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ExecuteResponse{
			Status: "error",
			Error:  fmt.Sprintf("failed to send command: %v", err),
		})
		return
	}

	// Close our write side to signal "command complete" to the agent.
	// NOTE: We must NOT use CancelWrite() here. CancelWrite sends a
	// RESET_STREAM frame, which causes the agent's io.ReadAll to receive
	// an error instead of a clean EOF. stream.Close() sends a proper FIN.
	stream.Close()

	// ── Read the agent's response ──────────────────────────────────────
	// Use the same timeout context to prevent blocking on a hung agent.
	responseCh := make(chan []byte, 1)
	errCh := make(chan error, 1)

	go func() {
		data, err := io.ReadAll(stream)
		if err != nil {
			errCh <- err
			return
		}
		responseCh <- data
	}()

	select {
	case <-timeoutCtx.Done():
		log.Printf("[API] ⚠ Timeout waiting for response from agent %q", req.AgentID)
		stream.Close()
		w.WriteHeader(http.StatusGatewayTimeout)
		json.NewEncoder(w).Encode(ExecuteResponse{
			Status: "error",
			Error:  fmt.Sprintf("agent %q did not respond within %v", req.AgentID, commandTimeout),
		})

	case err := <-errCh:
		log.Printf("[API] ⚠ Error reading response from agent %q: %v", req.AgentID, err)
		stream.Close()
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ExecuteResponse{
			Status: "error",
			Error:  fmt.Sprintf("failed to read agent response: %v", err),
		})

	case output := <-responseCh:
		log.Printf("[API] ✓ Command executed on agent %q (%d bytes response)",
			req.AgentID, len(output))
		stream.Close()
		json.NewEncoder(w).Encode(ExecuteResponse{
			Status: "ok",
			Output: string(output),
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// authenticateRequest — validates the Bearer token
// ─────────────────────────────────────────────────────────────────────────────
// Expects the Authorization header in the format: "Bearer <TOKEN>"
// Returns an error if the header is missing, malformed, or the token
// doesn't match.
// ─────────────────────────────────────────────────────────────────────────────

func (api *ControlAPI) authenticateRequest(r *http.Request) error {
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		return fmt.Errorf("missing Authorization header")
	}

	// Split "Bearer <token>" — must have exactly 2 parts.
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return fmt.Errorf("malformed Authorization header (expected 'Bearer <token>')")
	}

	token := strings.TrimSpace(parts[1])
	if token != api.bearerToken {
		return fmt.Errorf("invalid bearer token")
	}

	return nil
}
