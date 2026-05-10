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

	"github.com/AhirTech1/zero-trust-hive/internal/audit"
	"github.com/AhirTech1/zero-trust-hive/internal/auth"
	"github.com/AhirTech1/zero-trust-hive/internal/ratelimit"
)

const maxRequestBody = 1 << 20

// ExecuteRequest is the JSON body for POST /execute.
type ExecuteRequest struct {
	AgentID string `json:"agent_id"`
	Command string `json:"command"`
}

// ExecuteResponse is the JSON response from POST /execute.
type ExecuteResponse struct {
	Status   string `json:"status"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
	Error    string `json:"error,omitempty"`
	AgentID  string `json:"agent_id,omitempty"`
}

// ControlAPI serves the HTTP control endpoint.
type ControlAPI struct {
	router       *Router
	jwtValidator *auth.JWTValidator
	firewall     *SemanticFirewall
	auditLogger  *audit.Logger
	rateLimiter  *ratelimit.Limiter
	cmdTimeout   time.Duration
	server       *http.Server
}

// NewControlAPI creates the HTTP control API.
func NewControlAPI(router *Router, jwtSecret string, firewall *SemanticFirewall,
	auditLogger *audit.Logger, rateLimiter *ratelimit.Limiter, apiAddr string, cmdTimeout time.Duration) *ControlAPI {

	api := &ControlAPI{
		router:       router,
		jwtValidator: auth.NewJWTValidator(jwtSecret),
		firewall:     firewall,
		auditLogger:  auditLogger,
		rateLimiter:  rateLimiter,
		cmdTimeout:   cmdTimeout,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /execute", api.handleExecute)
	mux.HandleFunc("GET /agents", api.handleAgents)
	mux.HandleFunc("GET /health", api.handleHealth)

	var handler http.Handler = mux
	if rateLimiter != nil {
		handler = ratelimit.RateLimitMiddleware(rateLimiter)(mux)
	}

	api.server = &http.Server{
		Addr:         apiAddr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return api
}

// Start begins serving the HTTP control API.
func (api *ControlAPI) Start() error {
	log.Printf("[API] Control API listening on %s (TCP/HTTP)", api.server.Addr)
	log.Printf("[API]   POST /execute  — dispatch commands to agents (JWT required)")
	log.Printf("[API]   GET  /agents   — list connected agents (JWT required)")
	log.Printf("[API]   GET  /health   — gateway health check")
	if api.auditLogger.Enabled() {
		log.Printf("[API]   Audit logging  — enabled (JSON lines to stderr)")
	}

	if err := api.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("control API failed: %w", err)
	}
	return nil
}

// Shutdown gracefully stops the HTTP server.
func (api *ControlAPI) Shutdown(ctx context.Context) error {
	log.Printf("[API] Shutting down control API...")
	return api.server.Shutdown(ctx)
}

// handleHealth — GET /health (no auth).
func (api *ControlAPI) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	stats := api.firewall.Stats()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "healthy",
		"active_agents": api.router.Count(),
		"agents":        api.router.List(),
		"firewall": map[string]interface{}{
			"rules_loaded":    stats.RuleCount,
			"total_inspected": stats.TotalInspected,
			"total_blocked":   stats.TotalBlocked,
		},
	})
}

// handleAgents — GET /agents (JWT required).
func (api *ControlAPI) handleAgents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if _, err := api.authenticateRequest(r); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ExecuteResponse{
			Status: "error",
			Error:  fmt.Sprintf("unauthorized: %v", err),
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

// handleExecute — POST /execute.
func (api *ControlAPI) handleExecute(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	start := time.Now()

	claims, err := api.authenticateRequest(r)
	if err != nil {
		log.Printf("[API] JWT auth failed from %s: %v", r.RemoteAddr, err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ExecuteResponse{
			Status: "error",
			Error:  fmt.Sprintf("unauthorized: %v", err),
		})
		return
	}

	// Inject subject into context for rate limiter.
	ctx := context.WithValue(r.Context(), ratelimit.SubjectKey, claims.Subject)
	r = r.WithContext(ctx)

	log.Printf("[API] Authenticated: sub=%q scope=%q", claims.Subject, claims.Scope)

	body := http.MaxBytesReader(w, r.Body, maxRequestBody)
	defer body.Close()

	var req ExecuteRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ExecuteResponse{Status: "error", Error: fmt.Sprintf("invalid JSON body: %v", err)})
		return
	}

	if req.AgentID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ExecuteResponse{Status: "error", Error: "agent_id is required"})
		return
	}
	if req.Command == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ExecuteResponse{Status: "error", Error: "command is required"})
		return
	}

	// Semantic Firewall.
	if err := api.firewall.Inspect(req.Command); err != nil {
		log.Printf("[API] Firewall BLOCKED command to agent %q from %q: %v", req.AgentID, claims.Subject, err)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ExecuteResponse{
			Status:  "blocked",
			Error:   fmt.Sprintf("Firewall rejected command: %v", err),
			AgentID: req.AgentID,
		})
		api.recordAudit(claims.Subject, req.AgentID, req.Command, "blocked", time.Since(start))
		return
	}

	// Dispatch to agent.
	conn, err := api.router.Get(req.AgentID)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ExecuteResponse{
			Status: "error", Error: fmt.Sprintf("agent not found: %v", err),
		})
		api.recordAudit(claims.Subject, req.AgentID, req.Command, "error", time.Since(start))
		return
	}

	timeoutCtx, cancel := context.WithTimeout(r.Context(), api.cmdTimeout)
	defer cancel()

	stream, err := conn.OpenStreamSync(timeoutCtx)
	if err != nil {
		log.Printf("[API] Failed to open stream to agent %q: %v", req.AgentID, err)
		w.WriteHeader(http.StatusGatewayTimeout)
		json.NewEncoder(w).Encode(ExecuteResponse{
			Status: "error", Error: fmt.Sprintf("failed to reach agent: %v", err),
		})
		api.recordAudit(claims.Subject, req.AgentID, req.Command, "error", time.Since(start))
		return
	}

	if _, err := stream.Write([]byte(req.Command)); err != nil {
		log.Printf("[API] Failed to write command to agent %q: %v", req.AgentID, err)
		stream.Close()
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ExecuteResponse{Status: "error", Error: fmt.Sprintf("failed to send command: %v", err)})
		api.recordAudit(claims.Subject, req.AgentID, req.Command, "error", time.Since(start))
		return
	}
	stream.Close()

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
		log.Printf("[API] Timeout waiting for agent %q", req.AgentID)
		stream.Close()
		w.WriteHeader(http.StatusGatewayTimeout)
		json.NewEncoder(w).Encode(ExecuteResponse{
			Status: "error",
			Error:  fmt.Sprintf("agent %q did not respond within %v", req.AgentID, api.cmdTimeout),
		})
		api.recordAudit(claims.Subject, req.AgentID, req.Command, "timeout", time.Since(start))

	case err := <-errCh:
		log.Printf("[API] Error reading response from agent %q: %v", req.AgentID, err)
		stream.Close()
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ExecuteResponse{Status: "error", Error: fmt.Sprintf("failed to read agent response: %v", err)})
		api.recordAudit(claims.Subject, req.AgentID, req.Command, "error", time.Since(start))

	case output := <-responseCh:
		log.Printf("[API] Command executed on agent %q by %q (%d bytes response)", req.AgentID, claims.Subject, len(output))
		stream.Close()
		exitCode := 0
		json.NewEncoder(w).Encode(ExecuteResponse{
			Status:   "ok",
			Stdout:   string(output),
			Stderr:   "",
			ExitCode: &exitCode,
			AgentID:  req.AgentID,
		})
		api.recordAudit(claims.Subject, req.AgentID, req.Command, "ok", time.Since(start))
	}
}

func (api *ControlAPI) recordAudit(subject, agentID, command, status string, duration time.Duration) {
	if api.auditLogger == nil {
		return
	}
	api.auditLogger.Record(audit.Entry{
		Timestamp:  time.Now(),
		Subject:    subject,
		AgentID:    agentID,
		Command:    command,
		FirewallOK: status != "blocked",
		Status:     status,
		DurationMs: duration.Milliseconds(),
	})
}

func (api *ControlAPI) authenticateRequest(r *http.Request) (*auth.HiveClaims, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, fmt.Errorf("malformed Authorization header (expected 'Bearer <token>')")
	}

	return api.jwtValidator.ValidateToken(strings.TrimSpace(parts[1]))
}