// ─────────────────────────────────────────────────────────────────────────────
// Zero-Trust Hive — CLI Entry Point (Phase 4 Unified Mode)
// ─────────────────────────────────────────────────────────────────────────────
// Supports subcommands:
//
//	hive init                           - Interactive wizard for deployment
//	hive list                           - Queries gateway for active agents
//	hive exec -target <id> -cmd <json>  - Dispatches command via Gateway
//
// ─────────────────────────────────────────────────────────────────────────────
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/huh/spinner"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"

	hivaws "github.com/zero-trust-hive/cli/internal/aws"
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
	fmt.Println(lipgloss.JoinHorizontal(lipgloss.Left, tui.ValueStyle.Render("    init    "), tui.SubtleStyle.Render("Deploy Phase 1 infrastructure via interactive wizard")))
	fmt.Println(lipgloss.JoinHorizontal(lipgloss.Left, tui.ValueStyle.Render("    list    "), tui.SubtleStyle.Render("List active Edge Agents connected to the Cloud Gateway")))
	fmt.Println(lipgloss.JoinHorizontal(lipgloss.Left, tui.ValueStyle.Render("    exec    "), tui.SubtleStyle.Render("Execute a command or forward a payload to an Edge Agent")))
	fmt.Println()
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

	token := os.Getenv("HIVE_API_TOKEN")
	if token == "" {
		exitWithError("HIVE_API_TOKEN is not set", nil)
	}

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
	// Simply print the raw output (which might be JSON from the sidecar proxy).
	fmt.Println(string(execResp.Output))
}

// ─────────────────────────────────────────────────────────────────────────────
// runList — hive list
// ─────────────────────────────────────────────────────────────────────────────

func runList(args []string) {
	cmd := flag.NewFlagSet("list", flag.ExitOnError)
	cmd.Parse(args)

	token := os.Getenv("HIVE_API_TOKEN")
	if token == "" {
		exitWithError("HIVE_API_TOKEN is not set. Cannot authenticate to Gateway.", nil)
	}

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
// runInit — hive init (Phase 1 logic)
// ─────────────────────────────────────────────────────────────────────────────

func runInit(args []string) {
	cmd := flag.NewFlagSet("init", flag.ExitOnError)
	cmd.Parse(args)

	ctx := context.Background()

	fmt.Println(tui.RenderBanner())
	fmt.Println(tui.SubtleStyle.Render("  Welcome to the Zero-Trust Hive deployment engine."))
	fmt.Println(tui.SubtleStyle.Render("  This wizard will guide you through configuring your AWS deployment.\n"))

	fmt.Println(tui.AccentStyle.Render("  ▸ Scanning for AWS credentials...\n"))

	creds := hivaws.DiscoverCredentials()

	var awsCfg aws.Config
	var err error

	if creds.Found {
		fmt.Println(tui.SuccessStyle.Render(fmt.Sprintf("  ✓ Found: %s\n", creds.Source)))

		var useExisting bool
		confirmForm := huh.NewForm(
			huh.NewGroup(
				huh.NewConfirm().
					Title("Use detected AWS credentials?").
					Description(fmt.Sprintf("Source: %s", creds.Source)).
					Affirmative("Yes, use these").
					Negative("No, enter manually").
					Value(&useExisting),
			),
		).WithTheme(tui.CorporateTheme())

		if err := confirmForm.Run(); err != nil {
			exitWithError("Credential confirmation cancelled", err)
		}

		if useExisting {
			awsCfg, err = hivaws.BuildDefaultConfig(ctx, "")
			if err != nil {
				exitWithError("Failed to load AWS configuration", err)
			}
			fmt.Println(tui.SuccessStyle.Render("  ✓ AWS credentials loaded successfully.\n"))
		} else {
			awsCfg = promptManualCredentials(ctx)
		}
	} else {
		fmt.Println(tui.WarningStyle.Render("  ⚠ No existing AWS credentials detected.\n"))
		awsCfg = promptManualCredentials(ctx)
	}

	var regionOptions []huh.Option[string]
	spinnerErr := spinner.New().
		Title("  Fetching available AWS regions...").
		Action(func() {
			regionOptions, err = hivaws.FetchRegions(ctx, awsCfg)
		}).
		Run()

	if spinnerErr != nil || err != nil {
		exitWithError("Failed to fetch AWS regions", err)
	}

	fmt.Println(tui.SuccessStyle.Render(fmt.Sprintf("  ✓ Found %d available regions.\n", len(regionOptions))))

	var selectedRegion string
	regionForm := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Select Deployment Region").
				Description("Choose the AWS region for your deployment.").
				Options(regionOptions...).
				Value(&selectedRegion).
				Height(15),
		),
	).WithTheme(tui.CorporateTheme())

	if err := regionForm.Run(); err != nil {
		exitWithError("Region selection cancelled", err)
	}

	fmt.Println(tui.AccentStyle.Render(fmt.Sprintf("  ▸ Region selected: %s\n", selectedRegion)))

	awsCfg.Region = selectedRegion

	var instanceOptions []huh.Option[string]
	spinnerErr = spinner.New().
		Title(fmt.Sprintf("  Fetching instance types for %s...", selectedRegion)).
		Action(func() {
			instanceOptions, err = hivaws.FetchInstanceTypes(ctx, awsCfg)
		}).
		Run()

	if spinnerErr != nil || err != nil {
		exitWithError("Failed to fetch instance types", err)
	}

	fmt.Println(tui.SuccessStyle.Render(fmt.Sprintf("  ✓ Found %d instance types available.\n", len(instanceOptions))))

	var selectedInstance string
	instanceForm := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Select Instance Type").
				Description("Choose the EC2 instance type. Sorted by family.").
				Options(instanceOptions...).
				Value(&selectedInstance).
				Height(15),
		),
	).WithTheme(tui.CorporateTheme())

	if err := instanceForm.Run(); err != nil {
		exitWithError("Instance type selection cancelled", err)
	}

	fmt.Println(tui.AccentStyle.Render(fmt.Sprintf("  ▸ Instance type selected: %s\n", selectedInstance)))

	var amiOptions []huh.Option[string]
	spinnerErr = spinner.New().
		Title(fmt.Sprintf("  Fetching available AMIs for %s...", selectedRegion)).
		Action(func() {
			amiOptions, err = hivaws.FetchAMIs(ctx, awsCfg)
		}).
		Run()

	if spinnerErr != nil || err != nil {
		exitWithError("Failed to fetch AMIs", err)
	}

	fmt.Println(tui.SuccessStyle.Render(fmt.Sprintf("  ✓ Found %d available AMIs.\n", len(amiOptions))))

	var selectedAMI string
	amiForm := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Select Machine Image (AMI)").
				Options(amiOptions...).
				Value(&selectedAMI).
				Height(15),
		),
	).WithTheme(tui.CorporateTheme())

	if err := amiForm.Run(); err != nil {
		exitWithError("AMI selection cancelled", err)
	}

	fmt.Println(tui.AccentStyle.Render(fmt.Sprintf("  ▸ AMI selected: %s\n", selectedAMI)))

	var deploymentName string
	var confirmDeploy bool

	configForm := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Deployment Name").
				Placeholder("e.g., prod-hive-us-east").
				Validate(func(s string) error {
					if len(strings.TrimSpace(s)) < 3 {
						return fmt.Errorf("must be at least 3 characters")
					}
					return nil
				}).
				Value(&deploymentName),
		),
	).WithTheme(tui.CorporateTheme())

	if err := configForm.Run(); err != nil {
		exitWithError("Configuration cancelled", err)
	}

	summary := buildSummaryPanel(deploymentName, selectedRegion, selectedInstance, selectedAMI)
	fmt.Println(summary)

	confirmForm := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Deploy with these settings?").
				Affirmative("Yes, deploy").
				Negative("No, abort").
				Value(&confirmDeploy),
		),
	).WithTheme(tui.CorporateTheme())

	if err := confirmForm.Run(); err != nil {
		exitWithError("Confirmation cancelled", err)
	}

	if confirmDeploy {
		fmt.Println()
		fmt.Println(tui.SuccessStyle.Render("  ✓ Deployment configuration saved successfully."))
		fmt.Println(tui.SubtleStyle.Render("  Zero-Trust Hive is ready for deployment."))
	} else {
		fmt.Println()
		fmt.Println(tui.WarningStyle.Render("  ⚠ Deployment aborted by user."))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func promptManualCredentials(ctx context.Context) aws.Config {
	var accessKey, secretKey string
	credForm := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("AWS Access Key ID").Value(&accessKey),
			huh.NewInput().Title("AWS Secret Access Key").EchoMode(huh.EchoModePassword).Value(&secretKey),
		),
	).WithTheme(tui.CorporateTheme())

	if err := credForm.Run(); err != nil {
		exitWithError("Credential input cancelled", err)
	}

	cfg, err := hivaws.BuildStaticConfig(ctx, accessKey, secretKey, "us-east-1")
	if err != nil {
		exitWithError("Failed to build AWS configuration", err)
	}

	fmt.Println(tui.SuccessStyle.Render("  ✓ Credentials accepted.\n"))
	return cfg
}

func buildSummaryPanel(name, region, instance, ami string) string {
	header := tui.HeaderStyle.Render("  DEPLOYMENT SUMMARY  ")
	divider := tui.SubtleStyle.Render(strings.Repeat(tui.DividerChar, 50))

	labelStyle := lipgloss.NewStyle().Foreground(tui.ColorSlate).Width(22).Align(lipgloss.Right).PaddingRight(2)
	rows := []string{
		lipgloss.JoinHorizontal(lipgloss.Top, labelStyle.Render("Deployment Name"), tui.ValueStyle.Render(name)),
		lipgloss.JoinHorizontal(lipgloss.Top, labelStyle.Render("Region"), tui.ValueStyle.Render(region)),
		lipgloss.JoinHorizontal(lipgloss.Top, labelStyle.Render("Instance Type"), tui.ValueStyle.Render(instance)),
		lipgloss.JoinHorizontal(lipgloss.Top, labelStyle.Render("Machine Image (AMI)"), tui.ValueStyle.Render(ami)),
	}

	content := lipgloss.JoinVertical(lipgloss.Left, header, "", divider, "")
	for _, row := range rows {
		content = lipgloss.JoinVertical(lipgloss.Left, content, row)
	}
	content = lipgloss.JoinVertical(lipgloss.Left, content, "", divider)

	return tui.SummaryPanelStyle.Render(content)
}

func exitWithError(message string, err error) {
	fmt.Println()
	fmt.Println(tui.ErrorStyle.Render(fmt.Sprintf("  ✗ %s", message)))
	if err != nil {
		fmt.Println(tui.SubtleStyle.Render(fmt.Sprintf("    Error: %v", err)))
	}
	fmt.Println()
	os.Exit(1)
}
