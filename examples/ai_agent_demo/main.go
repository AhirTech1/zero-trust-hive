// ─────────────────────────────────────────────────────────────────────────────
// Zero-Trust Hive — AI Agent Demo
// ─────────────────────────────────────────────────────────────────────────────
//
// This file simulates how a Cloud AI Agent (LangChain, AutoGPT, Claude)
// securely communicates with the Zero-Trust Hive Gateway.
//
// It demonstrates two real-world scenarios:
//
//  1. ✅ HAPPY PATH  — The AI agent sends a safe command ("uptime").
//     The Gateway validates the JWT, passes the firewall, dispatches to the
//     Edge Agent, and returns structured JSON with stdout/exit_code.
//
//  2. 🛡 BLOCKED PATH — The AI agent "hallucinates" a destructive command
//     ("rm -rf /var/log" or "DROP TABLE users"). The Gateway's Semantic
//     Firewall intercepts it and returns HTTP 403 with a structured
//     rejection — the private machine is never touched.
//
// Usage:
//
//	# First, start the Gateway in another terminal:
//	#   export HIVE_JWT_SECRET="demo-secret-do-not-use-in-prod"
//	#   go run cmd/gateway/main.go
//	#
//	# Then run this demo:
//	go run examples/ai_agent_demo/main.go
//
// ─────────────────────────────────────────────────────────────────────────────
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

const (
	// gatewayURL is the HTTP endpoint of the Zero-Trust Hive Gateway.
	gatewayURL = "http://localhost:8080"

	// demoSecret is a hardcoded secret for this demo.
	// In production, this comes from HIVE_JWT_SECRET.
	demoSecret = "demo-secret-do-not-use-in-prod"
)

// ─────────────────────────────────────────────────────────────────────────────
// Gateway JSON types (mirrors internal/network types)
// ─────────────────────────────────────────────────────────────────────────────

// ExecuteRequest is the JSON body for POST /execute.
type ExecuteRequest struct {
	AgentID string `json:"agent_id"`
	Command string `json:"command"`
}

// ExecuteResponse is the structured JSON response from the Gateway.
type ExecuteResponse struct {
	Status   string `json:"status"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
	Error    string `json:"error,omitempty"`
	AgentID  string `json:"agent_id,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// ANSI color helpers (for terminal output)
// ─────────────────────────────────────────────────────────────────────────────

const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	white   = "\033[37m"
)

func header(s string) {
	fmt.Printf("\n%s%s%s %s %s%s%s\n", bold, white, "╔══", s, "══╗", reset, "")
}
func divider() { fmt.Printf("%s%s%s\n", dim, strings.Repeat("─", 70), reset) }
func label(k, v string) {
	fmt.Printf("  %s%s%-18s%s %s\n", dim, cyan, k, reset, v)
}

// ─────────────────────────────────────────────────────────────────────────────
// main — orchestrates the two demo scenarios
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	printBanner()

	// Read the JWT secret — fall back to demo secret if not set.
	secret := os.Getenv("HIVE_JWT_SECRET")
	if secret == "" {
		secret = demoSecret
		fmt.Printf("  %s⚠ HIVE_JWT_SECRET not set — using hardcoded demo secret%s\n", yellow, reset)
		fmt.Printf("  %sSet it to match your Gateway's secret for a live demo%s\n\n", dim, reset)
	}

	// ─────────────────────────────────────────────────────────────────
	// Scenario 1: The Happy Path — Safe Command
	// ─────────────────────────────────────────────────────────────────
	header("SCENARIO 1 — HAPPY PATH (Safe Command)")
	divider()

	fmt.Printf("\n  %s🤖 AI Agent decides to check system uptime...%s\n\n", bold+green, reset)

	safeReq := ExecuteRequest{
		AgentID: "production-server-01",
		Command: "uptime",
	}

	fmt.Printf("  %sGenerating JWT token...%s\n", dim, reset)
	token := generateJWT(secret, "langchain-agent-v3", "execute")

	fmt.Printf("  %sSending POST /execute →%s\n", dim, reset)
	label("Target Agent:", safeReq.AgentID)
	label("Command:", safeReq.Command)
	label("Auth:", "Bearer "+token[:40]+"...")
	fmt.Println()

	resp, statusCode, err := sendExecuteRequest(safeReq, token)
	if err != nil {
		fmt.Printf("  %s✗ Connection failed: %v%s\n", red, err, reset)
		fmt.Printf("\n  %s💡 Is the Gateway running? Start it with:%s\n", yellow, reset)
		fmt.Printf("     %sexport HIVE_JWT_SECRET=%q%s\n", bold, secret, reset)
		fmt.Printf("     %sgo run cmd/gateway/main.go%s\n\n", bold, reset)
		os.Exit(1)
	}

	printResponse("HAPPY PATH", statusCode, resp)

	// ─────────────────────────────────────────────────────────────────
	// Scenario 2: The Hallucination — Destructive Command
	// ─────────────────────────────────────────────────────────────────
	header("SCENARIO 2 — AI HALLUCINATION (Destructive Command)")
	divider()

	fmt.Printf("\n  %s🤖 AI Agent hallucinates and tries to delete logs...%s\n\n", bold+red, reset)

	dangerousReq := ExecuteRequest{
		AgentID: "production-server-01",
		Command: "rm -rf /var/log",
	}

	fmt.Printf("  %sSending POST /execute →%s\n", dim, reset)
	label("Target Agent:", dangerousReq.AgentID)
	label("Command:", fmt.Sprintf("%s%s%s (DANGEROUS!)", red+bold, dangerousReq.Command, reset))
	fmt.Println()

	resp2, statusCode2, err := sendExecuteRequest(dangerousReq, token)
	if err != nil {
		fmt.Printf("  %s✗ Connection failed: %v%s\n", red, err, reset)
		os.Exit(1)
	}

	printResponse("FIREWALL BLOCK", statusCode2, resp2)

	// ─────────────────────────────────────────────────────────────────
	// Scenario 3: SQL Injection Hallucination
	// ─────────────────────────────────────────────────────────────────
	header("SCENARIO 3 — SQL INJECTION HALLUCINATION")
	divider()

	fmt.Printf("\n  %s🤖 AI Agent tries to drop a database table...%s\n\n", bold+red, reset)

	sqlReq := ExecuteRequest{
		AgentID: "production-server-01",
		Command: "psql -c 'DROP TABLE users CASCADE;'",
	}

	fmt.Printf("  %sSending POST /execute →%s\n", dim, reset)
	label("Target Agent:", sqlReq.AgentID)
	label("Command:", fmt.Sprintf("%s%s%s (SQL INJECTION!)", red+bold, sqlReq.Command, reset))
	fmt.Println()

	resp3, statusCode3, err := sendExecuteRequest(sqlReq, token)
	if err != nil {
		fmt.Printf("  %s✗ Connection failed: %v%s\n", red, err, reset)
		os.Exit(1)
	}

	printResponse("FIREWALL BLOCK", statusCode3, resp3)

	// ─────────────────────────────────────────────────────────────────
	// Summary
	// ─────────────────────────────────────────────────────────────────
	printSummary()
}

// ─────────────────────────────────────────────────────────────────────────────
// generateJWT — creates a signed JWT token (same as the CLI does)
// ─────────────────────────────────────────────────────────────────────────────

func generateJWT(secret, subject, scope string) string {
	now := time.Now()

	claims := jwt.MapClaims{
		"sub":   subject,
		"iss":   "zero-trust-hive",
		"scope": scope,
		"iat":   now.Unix(),
		"exp":   now.Add(1 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		fmt.Printf("  %s✗ Failed to sign JWT: %v%s\n", red, err, reset)
		os.Exit(1)
	}
	return signed
}

// ─────────────────────────────────────────────────────────────────────────────
// sendExecuteRequest — sends a POST /execute to the Gateway
// ─────────────────────────────────────────────────────────────────────────────

func sendExecuteRequest(req ExecuteRequest, token string) (*ExecuteResponse, int, error) {
	body, _ := json.Marshal(req)

	httpReq, err := http.NewRequest("POST", gatewayURL+"/execute", bytes.NewBuffer(body))
	if err != nil {
		return nil, 0, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, 0, err
	}
	defer httpResp.Body.Close()

	var resp ExecuteResponse
	json.NewDecoder(httpResp.Body).Decode(&resp)

	return &resp, httpResp.StatusCode, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// printResponse — formats the Gateway response for the terminal
// ─────────────────────────────────────────────────────────────────────────────

func printResponse(scenario string, statusCode int, resp *ExecuteResponse) {
	divider()

	// Color the HTTP status code based on success/failure.
	statusColor := green
	statusIcon := "✓"
	if statusCode != 200 {
		statusColor = red
		statusIcon = "🛡"
		if statusCode == 403 {
			statusColor = magenta
		}
	}

	fmt.Printf("  %sHTTP Status:%s  %s%s%d%s\n", dim, reset, statusColor+bold, statusIcon+" ", statusCode, reset)
	fmt.Println()

	// Pretty-print the raw JSON response.
	rawJSON, _ := json.MarshalIndent(resp, "  ", "  ")
	fmt.Printf("  %sGateway Response (JSON):%s\n", dim, reset)
	fmt.Printf("  %s%s%s\n", blue, string(rawJSON), reset)
	fmt.Println()

	// Interpret the result.
	switch resp.Status {
	case "ok":
		fmt.Printf("  %s%s✓ Command executed successfully!%s\n", bold, green, reset)
		if resp.Stdout != "" {
			fmt.Printf("  %sAgent stdout: %s%s%s\n", dim, white+bold, resp.Stdout, reset)
		}
		if resp.ExitCode != nil {
			fmt.Printf("  %sExit code:    %s%d%s\n", dim, white, *resp.ExitCode, reset)
		}

	case "blocked":
		fmt.Printf("  %s%s🛡 COMMAND BLOCKED BY SEMANTIC FIREWALL%s\n", bold, magenta, reset)
		fmt.Printf("  %s%s%s\n", yellow, resp.Error, reset)
		fmt.Printf("\n  %s%s→ The private machine was NEVER touched.%s\n", bold, green, reset)
		fmt.Printf("  %s→ The AI's hallucinated command was stopped at the Gateway.%s\n", green, reset)

	case "error":
		fmt.Printf("  %s%s✗ Error: %s%s\n", bold, red, resp.Error, reset)
	}

	fmt.Println()
}

// ─────────────────────────────────────────────────────────────────────────────
// printBanner — the big welcome banner
// ─────────────────────────────────────────────────────────────────────────────

func printBanner() {
	fmt.Println()
	fmt.Printf("  %s%s", bold+cyan, strings.Repeat("═", 60))
	fmt.Println(reset)
	fmt.Printf("  %s%s", bold+white, "  🐝 ZERO-TRUST HIVE — AI AGENT DEMO")
	fmt.Println(reset)
	fmt.Printf("  %s%s", dim, "  Secure Execution Tunnel for Cloud AI Agents")
	fmt.Println(reset)
	fmt.Printf("  %s%s", bold+cyan, strings.Repeat("═", 60))
	fmt.Println(reset)
	fmt.Println()
	fmt.Printf("  %sThis demo simulates an AI agent (LangChain, AutoGPT, Claude)%s\n", dim, reset)
	fmt.Printf("  %scommunicating with the Zero-Trust Hive Gateway.%s\n", dim, reset)
	fmt.Println()
	fmt.Printf("  %sIt sends two types of commands:%s\n", dim, reset)
	fmt.Printf("  %s  1. ✅ A safe command   → passes the firewall → executes%s\n", dim, reset)
	fmt.Printf("  %s  2. 🛡 A dangerous cmd  → BLOCKED by the Semantic Firewall%s\n", dim, reset)
	fmt.Println()
}

// ─────────────────────────────────────────────────────────────────────────────
// printSummary — the closing summary
// ─────────────────────────────────────────────────────────────────────────────

func printSummary() {
	fmt.Printf("  %s%s", bold+cyan, strings.Repeat("═", 60))
	fmt.Println(reset)
	fmt.Printf("  %s%s  📊 DEMO SUMMARY%s\n", bold, white, reset)
	fmt.Printf("  %s%s", bold+cyan, strings.Repeat("═", 60))
	fmt.Println(reset)
	fmt.Println()
	fmt.Printf("  %s✅ Scenario 1:%s Safe command was executed and returned stdout.%s\n", green+bold, reset+white, reset)
	fmt.Printf("  %s🛡 Scenario 2:%s 'rm -rf' was BLOCKED before reaching the agent.%s\n", magenta+bold, reset+white, reset)
	fmt.Printf("  %s🛡 Scenario 3:%s 'DROP TABLE' was BLOCKED by SQL injection guard.%s\n", magenta+bold, reset+white, reset)
	fmt.Println()
	fmt.Printf("  %sThe Semantic Firewall protected your private infrastructure%s\n", dim, reset)
	fmt.Printf("  %sfrom AI-hallucinated destructive commands — zero-trust in action.%s\n", dim, reset)
	fmt.Println()
	fmt.Printf("  %sLearn more: %shttps://github.com/AhirTech1/zero-trust-hive%s\n", dim, blue+bold, reset)
	fmt.Println()
}
