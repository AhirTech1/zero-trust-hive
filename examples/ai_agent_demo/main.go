package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/AhirTech1/zero-trust-hive/internal/auth"
	"github.com/AhirTech1/zero-trust-hive/internal/network"
	"github.com/AhirTech1/zero-trust-hive/internal/tui"
)

const (
	gatewayURL = "http://localhost:8080"
	demoSecret = "demo-secret-do-not-use-in-prod"
)

func main() {
	printBanner()

	secret := os.Getenv("HIVE_JWT_SECRET")
	if secret == "" {
		secret = demoSecret
		fmt.Println(tui.WarningStyle.Render("  HIVE_JWT_SECRET not set — using hardcoded demo secret"))
		fmt.Println(tui.SubtleStyle.Render("  Set it to match your Gateway's secret for a live demo"))
		fmt.Println()
	}

	// ── Scenario 1: Happy Path ────────────────────────────────────────────────
	header("SCENARIO 1 — HAPPY PATH (Safe Command)")
	divider()

	fmt.Println(tui.SuccessStyle.Render("\n  AI Agent decides to check system uptime...\n"))

	safeReq := network.ExecuteRequest{
		AgentID: "production-server-01",
		Command: "uptime",
	}

	token := generateJWT(secret, "langchain-agent-v3", "execute")

	fmt.Println(tui.SubtleStyle.Render("  Sending POST /execute"))
	kv("Target Agent", safeReq.AgentID)
	kv("Command", safeReq.Command)
	kv("Auth", "Bearer "+token[:40]+"...")
	fmt.Println()

	resp, statusCode, err := sendExecuteRequest(safeReq, token)
	if err != nil {
		fmt.Println(tui.ErrorStyle.Render(fmt.Sprintf("  Connection failed: %v", err)))
		fmt.Printf("\n  Is the Gateway running? Start it with:\n")
		fmt.Printf("     export HIVE_JWT_SECRET=%q\n", secret)
		fmt.Printf("     go run cmd/gateway/main.go\n\n")
		os.Exit(1)
	}

	printResponse("HAPPY PATH", statusCode, resp)

	// ── Scenario 2: Hallucination — Destructive Command ───────────────────────
	header("SCENARIO 2 — AI HALLUCINATION (Destructive Command)")
	divider()

	fmt.Println(tui.WarningStyle.Render("\n  AI Agent hallucinates and tries to delete logs...\n"))

	dangerousReq := network.ExecuteRequest{
		AgentID: "production-server-01",
		Command: "rm -rf /var/log",
	}

	fmt.Println(tui.SubtleStyle.Render("  Sending POST /execute"))
	kv("Target Agent", dangerousReq.AgentID)
	kv("Command", tui.ErrorStyle.Render(dangerousReq.Command+" (DANGEROUS!)"))
	fmt.Println()

	resp2, statusCode2, _ := sendExecuteRequest(dangerousReq, token)
	printResponse("FIREWALL BLOCK", statusCode2, resp2)

	// ── Scenario 3: SQL Injection Hallucination ───────────────────────────────
	header("SCENARIO 3 — SQL INJECTION HALLUCINATION")
	divider()

	fmt.Println(tui.WarningStyle.Render("\n  AI Agent tries to drop a database table...\n"))

	sqlReq := network.ExecuteRequest{
		AgentID: "production-server-01",
		Command: "psql -c 'DROP TABLE users CASCADE;'",
	}

	fmt.Println(tui.SubtleStyle.Render("  Sending POST /execute"))
	kv("Target Agent", sqlReq.AgentID)
	kv("Command", tui.ErrorStyle.Render(sqlReq.Command+" (SQL INJECTION!)"))
	fmt.Println()

	resp3, statusCode3, _ := sendExecuteRequest(sqlReq, token)
	printResponse("FIREWALL BLOCK", statusCode3, resp3)

	printSummary()
}

func header(s string) {
	fmt.Printf("\n%s %s %s\n",
		tui.HeaderStyle.Render("  "+s+"  "),
		"",
		"",
	)
}

func divider() {
	fmt.Println(tui.SubtleStyle.Render(strings.Repeat(tui.DividerChar, 70)))
}

func kv(k, v string) {
	fmt.Printf("  %-18s %s\n", tui.SubtleStyle.Render(k+":"), v)
}

func generateJWT(secret, subject, scope string) string {
	token, err := auth.GenerateToken(secret, subject, scope)
	if err != nil {
		fmt.Println(tui.ErrorStyle.Render(fmt.Sprintf("  Failed to sign JWT: %v", err)))
		os.Exit(1)
	}
	return token
}

func sendExecuteRequest(req network.ExecuteRequest, token string) (*network.ExecuteResponse, int, error) {
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

	var resp network.ExecuteResponse
	json.NewDecoder(httpResp.Body).Decode(&resp)

	return &resp, httpResp.StatusCode, nil
}

func printResponse(scenario string, statusCode int, resp *network.ExecuteResponse) {
	divider()

	statusColor := tui.SuccessStyle
	if statusCode != 200 {
		statusColor = tui.ErrorStyle
		if statusCode == 403 {
			statusColor = tui.AccentStyle
		}
	}

	fmt.Println("  HTTP Status:  " + statusColor.Render(fmt.Sprintf("%d", statusCode)))
	fmt.Println()

	rawJSON, _ := json.MarshalIndent(resp, "  ", "  ")
	fmt.Println(tui.SubtleStyle.Render("  Gateway Response (JSON):"))
	fmt.Println(tui.ValueStyle.Render("  " + string(rawJSON)))
	fmt.Println()

	switch resp.Status {
	case "ok":
		fmt.Println(tui.SuccessStyle.Render("  Command executed successfully!"))
		if resp.Stdout != "" {
			fmt.Printf("  Agent stdout: %s\n", resp.Stdout)
		}
		if resp.ExitCode != nil {
			fmt.Printf("  Exit code:    %d\n", *resp.ExitCode)
		}

	case "blocked":
		fmt.Println(tui.WarningStyle.Render("  COMMAND BLOCKED BY SEMANTIC FIREWALL"))
		fmt.Println(tui.WarningStyle.Render("  " + resp.Error))
		fmt.Println(tui.SuccessStyle.Render("\n  The private machine was NEVER touched."))
		fmt.Println(tui.SuccessStyle.Render("  The AI's hallucinated command was stopped at the Gateway."))

	case "error":
		fmt.Println(tui.ErrorStyle.Render("  Error: " + resp.Error))
	}

	fmt.Println()
}

func printBanner() {
	fmt.Println()
	fmt.Println(tui.HeaderStyle.Render("  ZERO-TRUST HIVE — AI AGENT DEMO  "))
	fmt.Println(tui.SubtleStyle.Render("  Secure Execution Tunnel for Cloud AI Agents"))
	fmt.Println(strings.Repeat(tui.DividerChar, 60))
	fmt.Println()
	fmt.Println(tui.SubtleStyle.Render("  This demo simulates an AI agent (LangChain, AutoGPT, Claude)"))
	fmt.Println(tui.SubtleStyle.Render("  communicating with the Zero-Trust Hive Gateway."))
	fmt.Println()
	fmt.Println(tui.SubtleStyle.Render("  Three scenarios:"))
	fmt.Println(tui.SuccessStyle.Render("    1. Safe command        — passes firewall, executes on agent"))
	fmt.Println(tui.WarningStyle.Render("    2. Dangerous bash cmd  — BLOCKED by Semantic Firewall"))
	fmt.Println(tui.WarningStyle.Render("    3. SQL injection       — BLOCKED by SQL injection guard"))
	fmt.Println()
}

func printSummary() {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println(tui.HeaderStyle.Render("  DEMO SUMMARY  "))
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()
	fmt.Println(tui.SuccessStyle.Render("  Scenario 1: Safe command was executed and returned stdout."))
	fmt.Println(tui.WarningStyle.Render("  Scenario 2: 'rm -rf' was BLOCKED before reaching the agent."))
	fmt.Println(tui.WarningStyle.Render("  Scenario 3: 'DROP TABLE' was BLOCKED by SQL injection guard."))
	fmt.Println()
	fmt.Println(tui.SubtleStyle.Render("  The Semantic Firewall protected your private infrastructure"))
	fmt.Println(tui.SubtleStyle.Render("  from AI-hallucinated destructive commands — zero-trust in action."))
	fmt.Println()
	fmt.Println(tui.AccentStyle.Render("  https://github.com/AhirTech1/zero-trust-hive"))
	fmt.Println()
}