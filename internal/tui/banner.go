// Package tui — banner.go renders the branded ASCII art launch banner.
// This is the first thing the user sees when they run `hive init`.
// The banner uses the corporate color palette and is framed inside a
// double-border lipgloss panel for a professional, polished look.
package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
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

const (
	// Version — displayed in the banner tagline.
	Version = "v0.1.0"

	// Tagline — one-line description under the logo.
	Tagline = "Universal Zero-Trust Deployment Engine"
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
