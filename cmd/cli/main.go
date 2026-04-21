// ─────────────────────────────────────────────────────────────────────────────
// Zero-Trust Hive — CLI Entry Point
// ─────────────────────────────────────────────────────────────────────────────
// The operator and AI-agent-facing CLI for Zero-Trust Hive.
//
// Subcommands:
//
//	hive init                           - Generate a .env file with a secure token
//	hive list                           - Query the Gateway for active agents
//	hive exec -target <id> -cmd <json>  - Dispatch a command via the Gateway
//	hive help                           - Print the detailed operator manual
//
// ─────────────────────────────────────────────────────────────────────────────
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/huh/spinner"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"

	"github.com/zero-trust-hive/cli/internal/auth"
	"github.com/zero-trust-hive/cli/internal/network"
	"github.com/zero-trust-hive/cli/internal/tui"
)

const gatewayURL = "http://localhost:8080"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]

	switch subcommand {
	case "init":
		runInit(os.Args[2:])
	case "list":
		runList(os.Args[2:])
	case "exec":
		runExec(os.Args[2:])
	case "help":
		printHelp()
	default:
		fmt.Println(tui.ErrorStyle.Render(fmt.Sprintf("  ✗ Unknown command: %s\n", subcommand)))
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(tui.RenderBanner())
	fmt.Println(tui.AccentStyle.Render("  Usage: hive <command> [arguments]"))
	fmt.Println("\n  Commands:")
	fmt.Println(lipgloss.JoinHorizontal(lipgloss.Left, tui.ValueStyle.Render("    init    "), tui.SubtleStyle.Render("Generate a secure .env configuration file")))
	fmt.Println(lipgloss.JoinHorizontal(lipgloss.Left, tui.ValueStyle.Render("    list    "), tui.SubtleStyle.Render("List active Edge Agents connected to the Cloud Gateway")))
	fmt.Println(lipgloss.JoinHorizontal(lipgloss.Left, tui.ValueStyle.Render("    exec    "), tui.SubtleStyle.Render("Execute a command or forward a payload to an Edge Agent")))
	fmt.Println(lipgloss.JoinHorizontal(lipgloss.Left, tui.ValueStyle.Render("    help    "), tui.SubtleStyle.Render("Show the comprehensive CLI manual")))
	fmt.Println()
	fmt.Println(tui.SubtleStyle.Render("  Run 'hive help' for detailed instructions and examples."))
	fmt.Println()
}

func printHelp() {
	fmt.Println(tui.RenderBanner())

	fmt.Println(tui.HeaderStyle.Render("  OPERATOR MANUAL  "))
	fmt.Println(tui.SubtleStyle.Render(strings.Repeat(tui.DividerChar, 80)))
	fmt.Println()

	fmt.Println(tui.AccentStyle.Render("  1. INITIALIZATION (hive init)"))
	fmt.Println(tui.SubtleStyle.Render("     Generates a .env file containing a cryptographically secure HIVE_JWT_SECRET"))
	fmt.Println(tui.SubtleStyle.Render("     and a signed bootstrap JWT token for immediate use."))
	fmt.Println()
	fmt.Println(tui.ValueStyle.Render("     Usage: hive init"))
	fmt.Println()

	fmt.Println(tui.AccentStyle.Render("  2. FLEET MONITORING (hive list)"))
	fmt.Println(tui.SubtleStyle.Render("     Queries the Cloud Gateway API and returns a real-time table of all Edge Agents"))
	fmt.Println(tui.SubtleStyle.Render("     that currently have an active, established QUIC tunnel."))
	fmt.Println()
	fmt.Println(tui.ValueStyle.Render("     Usage: hive list"))
	fmt.Println(tui.WarningStyle.Render("     Requires: HIVE_JWT_SECRET environment variable"))
	fmt.Println()

	fmt.Println(tui.AccentStyle.Render("  3. COMMAND EXECUTION & PROXYING (hive exec)"))
	fmt.Println(tui.SubtleStyle.Render("     Dispatches payloads down the reverse QUIC tunnel to a specific Edge Agent."))
	fmt.Println(tui.SubtleStyle.Render("     All commands pass through the Gateway's Semantic Firewall which blocks"))
	fmt.Println(tui.SubtleStyle.Render("     AI-hallucinated destructive strings (e.g., rm -rf) and SQL injection."))
	fmt.Println()
	fmt.Println(tui.SubtleStyle.Render("     Use JSON Envelopes to instruct the Agent Sidecar to proxy native HTTP/TCP"))
	fmt.Println(tui.SubtleStyle.Render("     requests to local databases, APIs, or microservices."))
	fmt.Println()
	fmt.Println(tui.ValueStyle.Render("     Usage: hive exec -target <agent-id> -cmd <payload>"))
	fmt.Println(tui.WarningStyle.Render("     Requires: HIVE_JWT_SECRET environment variable"))
	fmt.Println()
	fmt.Println(tui.ValueStyle.Render("     Direct Execution Example:"))
	fmt.Println(tui.SubtleStyle.Render("     hive exec -target node-01 -cmd 'uptime'"))
	fmt.Println()
	fmt.Println(tui.ValueStyle.Render("     Envelope Proxy Example:"))
	fmt.Println(tui.SubtleStyle.Render("     hive exec -target node-01 -cmd '{\"routing\":{\"protocol\":\"http\",\"target\":\"127.0.0.1:9090\"},\"payload\":\"...\"}'"))
	fmt.Println()

	fmt.Println(tui.SubtleStyle.Render(strings.Repeat(tui.DividerChar, 80)))
}

// ─────────────────────────────────────────────────────────────────────────────
// runExec — hive exec
// ─────────────────────────────────────────────────────────────────────────────

func runExec(args []string) {
	cmd := flag.NewFlagSet("exec", flag.ExitOnError)
	target := cmd.String("target", "", "Target Agent ID")
	payload := cmd.String("cmd", "", "Command or JSON Envelope to send")
	cmd.Parse(args)

	if *target == "" || *payload == "" {
		fmt.Println(tui.ErrorStyle.Render("  ✗ Both -target and -cmd are required."))
		fmt.Println("  Example: hive exec -target agent-001 -cmd 'uptime'")
		os.Exit(1)
	}

	// Generate a short-lived JWT from the shared secret.
	token := getJWT("hive-cli", "execute")

	reqBody := network.ExecuteRequest{
		AgentID: *target,
		Command: *payload,
	}

	b, _ := json.Marshal(reqBody)
	req, err := http.NewRequest("POST", gatewayURL+"/execute", bytes.NewBuffer(b))
	if err != nil {
		exitWithError("Failed to create request", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	fmt.Println(tui.SubtleStyle.Render(fmt.Sprintf("  ▸ Dispatching to %s...", *target)))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		exitWithError("Failed to reach Gateway API", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	var execResp network.ExecuteResponse
	json.Unmarshal(bodyBytes, &execResp)

	if resp.StatusCode != 200 {
		fmt.Println(tui.ErrorStyle.Render(fmt.Sprintf("  ✗ Gateway Error (HTTP %d)", resp.StatusCode)))
		if execResp.Error != "" {
			fmt.Println(tui.ValueStyle.Render("    " + execResp.Error))
		} else {
			fmt.Println(tui.ValueStyle.Render("    " + string(bodyBytes)))
		}
		os.Exit(1)
	}

	fmt.Println(tui.SuccessStyle.Render("  ✓ Execution Successful:"))
	fmt.Println()
	// Print the structured stdout from the agent.
	fmt.Println(string(execResp.Stdout))
}

// ─────────────────────────────────────────────────────────────────────────────
// runList — hive list
// ─────────────────────────────────────────────────────────────────────────────

func runList(args []string) {
	cmd := flag.NewFlagSet("list", flag.ExitOnError)
	cmd.Parse(args)

	// Generate a short-lived JWT from the shared secret.
	token := getJWT("hive-cli", "read")

	req, err := http.NewRequest("GET", gatewayURL+"/agents", nil)
	if err != nil {
		exitWithError("Failed to create request", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	// Fetch
	var fetchErr error
	var agents []network.AgentInfo

	spinnerErr := spinner.New().
		Title("  Querying active agents from Gateway...").
		Action(func() {
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				fetchErr = err
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusUnauthorized {
				fetchErr = fmt.Errorf("authentication failed (HTTP 401) — check HIVE_API_TOKEN")
				return
			}

			if resp.StatusCode != 200 {
				body, _ := io.ReadAll(resp.Body)
				fetchErr = fmt.Errorf("Gateway returned HTTP %d: %s", resp.StatusCode, string(body))
				return
			}

			var result struct {
				Agents []network.AgentInfo `json:"agents"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				fetchErr = err
				return
			}
			agents = result.Agents
		}).
		Run()

	if spinnerErr != nil || fetchErr != nil {
		exitWithError("Failed to list agents", fetchErr)
	}

	// Calculate terminal width for responsive layout
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width < 40 {
		width = 80 // fallback
	}

	if len(agents) == 0 {
		fmt.Println(tui.WarningStyle.Render("  ⚠ No active agents connected to the Gateway."))
		return
	}

	fmt.Println(tui.HeaderStyle.Render(fmt.Sprintf("  ACTIVE AGENTS (%d)  ", len(agents))))
	fmt.Println(tui.SubtleStyle.Render(strings.Repeat(tui.DividerChar, width-4)))

	idStyle := lipgloss.NewStyle().Foreground(tui.ColorAccentBlue).Width(width / 3)
	uptimeStyle := lipgloss.NewStyle().Foreground(tui.ColorSlate).Width(width / 3)
	timeStyle := lipgloss.NewStyle().Foreground(tui.ColorDarkGray).Width(width / 3)

	// Header row
	fmt.Println(lipgloss.JoinHorizontal(lipgloss.Left,
		idStyle.Render("  AGENT ID"),
		uptimeStyle.Render("UPTIME"),
		timeStyle.Render("CONNECTED AT"),
	))

	for _, a := range agents {
		fmt.Println(lipgloss.JoinHorizontal(lipgloss.Left,
			idStyle.Render("  "+a.AgentID),
			uptimeStyle.Render(a.Uptime),
			timeStyle.Render(a.ConnectedAt.Format(time.RFC3339)),
		))
	}
	fmt.Println(tui.SubtleStyle.Render(strings.Repeat(tui.DividerChar, width-4)))
}

// ─────────────────────────────────────────────────────────────────────────────
// runInit — hive init (Cloud-Agnostic Bootstrap)
// ─────────────────────────────────────────────────────────────────────────────
// Generates a .env file with a cryptographically random HIVE_API_TOKEN and
// prints clear instructions for deploying the Gateway on any cloud provider.
// ─────────────────────────────────────────────────────────────────────────────

func runInit(_ []string) {
	fmt.Println(tui.RenderBanner())
	fmt.Println(tui.SubtleStyle.Render("  Initializing Zero-Trust Hive configuration...\n"))

	// Generate a cryptographically secure 32-byte hex secret.
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		exitWithError("Failed to generate secure secret — system entropy exhausted", err)
	}
	jwtSecret := hex.EncodeToString(secretBytes)

	// Generate a bootstrap JWT token signed with this secret.
	bootstrapToken, err := auth.GenerateToken(jwtSecret, "hive-admin", "admin")
	if err != nil {
		exitWithError("Failed to generate bootstrap JWT", err)
	}

	// Write the .env file.
	envContent := fmt.Sprintf(`# Zero-Trust Hive — Generated Configuration
# Created by 'hive init'

# HMAC-SHA256 secret for JWT token signing/validation.
# The Gateway and CLI must share this secret.
HIVE_JWT_SECRET=%s

# Bootstrap JWT token (valid 24 hours, scope: admin).
# Use this immediately to authenticate with the Gateway.
HIVE_BOOTSTRAP_TOKEN=%s
`, jwtSecret, bootstrapToken)

	if err := os.WriteFile(".env", []byte(envContent), 0600); err != nil {
		exitWithError("Failed to write .env file", err)
	}

	fmt.Println(tui.SuccessStyle.Render("  ✓ Generated .env with HIVE_JWT_SECRET and bootstrap token"))
	fmt.Println()

	// Print the deployment instructions.
	fmt.Println(tui.HeaderStyle.Render("  DEPLOYMENT INSTRUCTIONS  "))
	divider := tui.SubtleStyle.Render(strings.Repeat(tui.DividerChar, 60))
	fmt.Println(divider)
	fmt.Println()

	fmt.Println(tui.AccentStyle.Render("  Step 1: Start the Gateway (on your cloud server)"))
	fmt.Println(tui.SubtleStyle.Render("  Copy the .env file to your server and run:"))
	fmt.Println()
	fmt.Println(tui.ValueStyle.Render("    export HIVE_JWT_SECRET=\"" + jwtSecret + "\""))
	fmt.Println(tui.ValueStyle.Render("    sudo -E gateway"))
	fmt.Println()

	fmt.Println(tui.AccentStyle.Render("  Step 2: Connect an Edge Agent (on your private machine)"))
	fmt.Println(tui.SubtleStyle.Render("  The agent dials out — no firewall changes needed."))
	fmt.Println()
	fmt.Println(tui.ValueStyle.Render("    agent -gateway <SERVER_IP>:443 -id my-private-server"))
	fmt.Println()

	fmt.Println(tui.AccentStyle.Render("  Step 3: Execute from your AI Agent or CLI"))
	fmt.Println(tui.SubtleStyle.Render("  Your LangChain/AutoGPT agent authenticates with a signed JWT:"))
	fmt.Println()
	fmt.Println(tui.ValueStyle.Render("    POST http://<SERVER_IP>:8080/execute"))
	fmt.Println(tui.ValueStyle.Render("    Authorization: Bearer <JWT_TOKEN>"))
	fmt.Println(tui.ValueStyle.Render("    {\"agent_id\": \"my-private-server\", \"command\": \"uptime\"}"))
	fmt.Println()
	fmt.Println(divider)

	fmt.Println()
	fmt.Println(tui.WarningStyle.Render("  ⚠ Keep your .env file secure. It contains your JWT signing secret."))
	fmt.Println()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func exitWithError(message string, err error) {
	fmt.Println()
	fmt.Println(tui.ErrorStyle.Render(fmt.Sprintf("  ✗ %s", message)))
	if err != nil {
		fmt.Println(tui.SubtleStyle.Render(fmt.Sprintf("    Error: %v", err)))
	}
	fmt.Println()
	os.Exit(1)
}

// getJWT reads HIVE_JWT_SECRET and generates a short-lived JWT for API calls.
func getJWT(subject, scope string) string {
	secret := os.Getenv("HIVE_JWT_SECRET")
	if secret == "" {
		exitWithError("HIVE_JWT_SECRET is not set. Run 'hive init' to generate one.", nil)
	}

	token, err := auth.GenerateToken(secret, subject, scope)
	if err != nil {
		exitWithError("Failed to generate JWT token", err)
	}
	return token
}
