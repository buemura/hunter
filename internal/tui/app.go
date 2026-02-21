package tui

import (
	"fmt"

	"github.com/buemura/hunter/internal/scanner"
	tea "github.com/charmbracelet/bubbletea"
)

// Run starts the interactive TUI with the given scanner registry.
func Run(reg *scanner.Registry) error {
	m := NewModel(reg)
	p := tea.NewProgram(m, tea.WithAltScreen())

	if _, err := p.Run(); err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

	return nil
}
