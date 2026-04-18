// Package tui provides the Terminal UI components for the Zero-Trust Hive CLI.
// This file defines the corporate design system — colors, styles, and a custom
// huh form theme that enforces a professional, structured aesthetic.
package tui

import (
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

// ─────────────────────────────────────────────────────────────────────────────
// Color Palette — Corporate Professional
// ─────────────────────────────────────────────────────────────────────────────
// Every color token used in the CLI is defined here. Zero magic values in the
// rest of the codebase; everything references these constants.
// ─────────────────────────────────────────────────────────────────────────────

const (
	// Primary brand colors — deep navy/blue spectrum
	ColorNavy       = lipgloss.Color("#1B2A4A") // Darkest background panels
	ColorMidBlue    = lipgloss.Color("#2D4A7A") // Secondary panels, borders
	ColorAccentBlue = lipgloss.Color("#3498DB") // Interactive highlights, focus
	ColorSkyBlue    = lipgloss.Color("#5DADE2") // Hover / secondary accent

	// Neutral palette — text hierarchy
	ColorWhite    = lipgloss.Color("#ECF0F1") // Primary text (headings, values)
	ColorSlate    = lipgloss.Color("#95A5A6") // Secondary text (labels, help)
	ColorDarkGray = lipgloss.Color("#2C3E50") // Muted backgrounds

	// Semantic colors — status indicators
	ColorSuccess = lipgloss.Color("#27AE60") // Confirmations, success states
	ColorError   = lipgloss.Color("#E74C3C") // Errors, warnings
	ColorWarning = lipgloss.Color("#F39C12") // Caution, progress indicators
	ColorTeal    = lipgloss.Color("#1ABC9C") // Info badges, secondary success
)

// ─────────────────────────────────────────────────────────────────────────────
// Reusable Lipgloss Styles
// ─────────────────────────────────────────────────────────────────────────────
// These styles are composed once and imported by every module that renders text.
// ─────────────────────────────────────────────────────────────────────────────

var (
	// HeaderStyle — used for section headings and the main banner.
	HeaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorWhite).
			Background(ColorNavy).
			Padding(0, 2)

	// PanelStyle — wraps content blocks in a bordered corporate panel.
	PanelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorMidBlue).
			Padding(1, 2).
			Margin(1, 0)

	// BannerStyle — the outer frame for the ASCII art launch banner.
	BannerStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(ColorAccentBlue).
			Padding(1, 4).
			Margin(1, 0).
			Align(lipgloss.Center)

	// SuccessStyle — for confirmation messages and success indicators.
	SuccessStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorSuccess)

	// ErrorStyle — for error messages and failure indicators.
	ErrorStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorError)

	// WarningStyle — for progress indicators and caution messages.
	WarningStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorWarning)

	// AccentStyle — for interactive elements and highlighted values.
	AccentStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorAccentBlue)

	// SubtleStyle — for secondary text, help hints, and labels.
	SubtleStyle = lipgloss.NewStyle().
			Foreground(ColorSlate)

	// ValueStyle — for displaying user-selected values in summaries.
	ValueStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorSkyBlue)

	// SummaryPanelStyle — the final deployment summary panel.
	SummaryPanelStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(ColorSuccess).
				Padding(1, 3).
				Margin(1, 0)

	// StatusBadge — small inline badge for tagging status labels.
	StatusBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorNavy).
			Background(ColorAccentBlue).
			Padding(0, 1)

	// DividerStyle — a horizontal rule between sections.
	DividerChar = "─"
)

// ─────────────────────────────────────────────────────────────────────────────
// Custom huh Theme
// ─────────────────────────────────────────────────────────────────────────────
// The default huh theme is overridden to match our corporate palette. This
// ensures every form field, selector, and confirmation prompt uses the same
// deep-blue + white aesthetic. We start from the Base() theme and restyle
// every component to remove any "hacker terminal" feel.
// ─────────────────────────────────────────────────────────────────────────────

// CorporateTheme returns a fully customized huh theme that aligns with the
// Zero-Trust Hive corporate design language.
func CorporateTheme() *huh.Theme {
	t := huh.ThemeBase()

	// ── Focused state: active input fields ─────────────────────────────
	t.Focused.Base = t.Focused.Base.
		BorderForeground(ColorAccentBlue)

	t.Focused.Title = t.Focused.Title.
		Foreground(ColorWhite).
		Bold(true)

	t.Focused.Description = t.Focused.Description.
		Foreground(ColorSlate)

	t.Focused.ErrorIndicator = t.Focused.ErrorIndicator.
		Foreground(ColorError)

	t.Focused.ErrorMessage = t.Focused.ErrorMessage.
		Foreground(ColorError)

	t.Focused.SelectSelector = t.Focused.SelectSelector.
		Foreground(ColorAccentBlue)

	t.Focused.Option = t.Focused.Option.
		Foreground(ColorWhite)

	t.Focused.MultiSelectSelector = t.Focused.MultiSelectSelector.
		Foreground(ColorAccentBlue)

	t.Focused.SelectedOption = t.Focused.SelectedOption.
		Foreground(ColorSuccess)

	t.Focused.SelectedPrefix = t.Focused.SelectedPrefix.
		Foreground(ColorSuccess)

	t.Focused.UnselectedOption = t.Focused.UnselectedOption.
		Foreground(ColorSlate)

	t.Focused.UnselectedPrefix = t.Focused.UnselectedPrefix.
		Foreground(ColorSlate)

	t.Focused.FocusedButton = t.Focused.FocusedButton.
		Foreground(ColorNavy).
		Background(ColorAccentBlue).
		Bold(true)

	t.Focused.BlurredButton = t.Focused.BlurredButton.
		Foreground(ColorSlate).
		Background(ColorDarkGray)

	t.Focused.TextInput.Cursor = t.Focused.TextInput.Cursor.
		Foreground(ColorAccentBlue)

	t.Focused.TextInput.Placeholder = t.Focused.TextInput.Placeholder.
		Foreground(ColorSlate)

	t.Focused.TextInput.Prompt = t.Focused.TextInput.Prompt.
		Foreground(ColorAccentBlue)

	// ── Blurred state: inactive fields ─────────────────────────────────
	t.Blurred.Base = t.Blurred.Base.
		BorderForeground(ColorDarkGray)

	t.Blurred.Title = t.Blurred.Title.
		Foreground(ColorSlate)

	t.Blurred.Description = t.Blurred.Description.
		Foreground(ColorDarkGray)

	t.Blurred.TextInput.Placeholder = t.Blurred.TextInput.Placeholder.
		Foreground(ColorDarkGray)

	t.Blurred.TextInput.Prompt = t.Blurred.TextInput.Prompt.
		Foreground(ColorDarkGray)

	// ── Help bar at the bottom ─────────────────────────────────────────
	t.Help.Ellipsis = t.Help.Ellipsis.Foreground(ColorSlate)
	t.Help.ShortKey = t.Help.ShortKey.Foreground(ColorAccentBlue)
	t.Help.ShortDesc = t.Help.ShortDesc.Foreground(ColorSlate)
	t.Help.ShortSeparator = t.Help.ShortSeparator.Foreground(ColorDarkGray)
	t.Help.FullKey = t.Help.FullKey.Foreground(ColorAccentBlue)
	t.Help.FullDesc = t.Help.FullDesc.Foreground(ColorSlate)
	t.Help.FullSeparator = t.Help.FullSeparator.Foreground(ColorDarkGray)

	return t
}
