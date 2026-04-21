// Package tui — banner.go renders the branded ASCII art launch banner.
// This is the first thing the user sees when they run `hive init`.
// The banner uses the corporate color palette and is framed inside a
// double-border lipgloss panel for a professional, polished look.
package tui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

// ─────────────────────────────────────────────────────────────────────────────
// ASCII Art
// ─────────────────────────────────────────────────────────────────────────────
// The project name rendered in block letters. This is static text (not
// generated) to guarantee pixel-perfect alignment in every terminal.
// ─────────────────────────────────────────────────────────────────────────────

const asciiLogo = `
 ███████╗███████╗██████╗  ██████╗       ████████╗██████╗ ██╗   ██╗███████╗████████╗
 ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗      ╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
   ███╔╝ █████╗  ██████╔╝██║   ██║         ██║   ██████╔╝██║   ██║███████╗   ██║   
  ███╔╝  ██╔══╝  ██╔══██╗██║   ██║         ██║   ██╔══██╗██║   ██║╚════██║   ██║   
 ███████╗███████╗██║  ██║╚██████╔╝         ██║   ██║  ██║╚██████╔╝███████║   ██║   
 ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝          ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
                    ██╗  ██╗██╗██╗   ██╗███████╗
                    ██║  ██║██║██║   ██║██╔════╝
                    ███████║██║██║   ██║█████╗  
                    ██╔══██║██║╚██╗ ██╔╝██╔══╝  
                    ██║  ██║██║ ╚████╔╝ ███████╗
                    ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝`

var (
	// Version — displayed in the banner tagline. Overridden by goreleaser via ldflags.
	Version = "v0.1.0"
)

const (
	// Tagline — one-line description under the logo.
	Tagline = "Secure AI Agent Execution Tunnel"
)

// ─────────────────────────────────────────────────────────────────────────────
// RenderBanner builds and returns the full branded launch banner string.
// ─────────────────────────────────────────────────────────────────────────────
// Layout:
//   ╔══════════════════════════════════════════╗
//   ║          [ASCII ART — accent blue]       ║
//   ║                                          ║
//   ║   Universal Zero-Trust Deployment Engine ║
//   ║               v0.1.0                     ║
//   ╚══════════════════════════════════════════╝
// ─────────────────────────────────────────────────────────────────────────────

func RenderBanner() string {
	// Style the ASCII art itself with the accent blue color.
	logoStyle := lipgloss.NewStyle().
		Foreground(ColorAccentBlue).
		Bold(true)

	// Tagline sits below the logo in white.
	taglineStyle := lipgloss.NewStyle().
		Foreground(ColorWhite).
		Bold(true).
		Align(lipgloss.Center)

	// Version badge — smaller, muted.
	versionStyle := lipgloss.NewStyle().
		Foreground(ColorSlate).
		Align(lipgloss.Center)

	// Get terminal width to prevent ASCII distortion
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err == nil && width < 100 {
		// Terminal is too narrow; render a compressed text fallback
		inner := lipgloss.JoinVertical(
			lipgloss.Center,
			logoStyle.Render("ZERO-TRUST HIVE"),
			taglineStyle.Render(Tagline),
			versionStyle.Render(fmt.Sprintf("Version %s", Version)),
		)
		return BannerStyle.Render(inner)
	}

	// Thin divider line between logo and tagline.
	dividerStyle := lipgloss.NewStyle().
		Foreground(ColorMidBlue)

	// Build the divider to match the logo width.
	divider := dividerStyle.Render(strings.Repeat(DividerChar, 60))

	// Compose the inner content: logo → divider → tagline → version.
	inner := lipgloss.JoinVertical(
		lipgloss.Center,
		logoStyle.Render(asciiLogo),
		"",
		divider,
		"",
		taglineStyle.Render(Tagline),
		versionStyle.Render(fmt.Sprintf("Version %s", Version)),
	)

	// Wrap in the double-border banner frame.
	return BannerStyle.Render(inner)
}
