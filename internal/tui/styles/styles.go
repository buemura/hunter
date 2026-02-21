package styles

import "github.com/charmbracelet/lipgloss"

// Severity colors.
var (
	ColorCritical = lipgloss.Color("#FF0000")
	ColorHigh     = lipgloss.Color("#FF6600")
	ColorMedium   = lipgloss.Color("#FFCC00")
	ColorLow      = lipgloss.Color("#00CC00")
	ColorInfo     = lipgloss.Color("#0099FF")
	ColorMuted    = lipgloss.Color("#666666")
	ColorAccent   = lipgloss.Color("#7D56F4")
)

// Styles used across TUI views.
var (
	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(ColorAccent).
			Padding(0, 1)

	HeaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorAccent).
			MarginBottom(1)

	BorderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorAccent).
			Padding(1, 2)

	SelectedStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorAccent)

	CursorStyle = lipgloss.NewStyle().
			Foreground(ColorAccent)

	HelpStyle = lipgloss.NewStyle().
			Foreground(ColorMuted)

	ErrorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF0000")).
			Bold(true)

	SeverityCriticalStyle = lipgloss.NewStyle().Bold(true).Foreground(ColorCritical)
	SeverityHighStyle     = lipgloss.NewStyle().Bold(true).Foreground(ColorHigh)
	SeverityMediumStyle   = lipgloss.NewStyle().Bold(true).Foreground(ColorMedium)
	SeverityLowStyle      = lipgloss.NewStyle().Foreground(ColorLow)
	SeverityInfoStyle     = lipgloss.NewStyle().Foreground(ColorInfo)
)

// SeverityStyle returns the appropriate style for a severity level.
func SeverityStyle(severity string) lipgloss.Style {
	switch severity {
	case "CRITICAL":
		return SeverityCriticalStyle
	case "HIGH":
		return SeverityHighStyle
	case "MEDIUM":
		return SeverityMediumStyle
	case "LOW":
		return SeverityLowStyle
	case "INFO":
		return SeverityInfoStyle
	default:
		return lipgloss.NewStyle()
	}
}
