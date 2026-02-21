package views

import (
	"context"
	"fmt"
	"strings"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/internal/tui/styles"
	"github.com/buemura/hunter/pkg/types"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ScanCompleteMsg is sent when a scan finishes.
type ScanCompleteMsg struct {
	Result types.ScanResult
}

// scanErrorMsg is sent when a scan encounters an error.
type scanErrorMsg struct {
	err error
}

// ScanModel is the view model for the scan progress view.
type ScanModel struct {
	spinner     spinner.Model
	scanner     scanner.Scanner
	target      types.Target
	done        bool
	err         string
	result      types.ScanResult
}

// NewScanModel creates a scan progress view for the given scanner and target.
func NewScanModel(s scanner.Scanner, target types.Target) ScanModel {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(styles.ColorAccent)

	return ScanModel{
		spinner: sp,
		scanner: s,
		target:  target,
	}
}

// Init starts the spinner and launches the scan.
func (m ScanModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, m.runScan())
}

// Update handles spinner ticks and scan completion.
func (m ScanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case ScanCompleteMsg:
		m.done = true
		m.result = msg.Result
		return m, nil

	case scanErrorMsg:
		m.done = true
		m.err = msg.err.Error()
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

// View renders the scan progress.
func (m ScanModel) View() string {
	var b strings.Builder

	b.WriteString(styles.TitleStyle.Render("Hunter — Interactive Mode"))
	b.WriteString("\n\n")

	if m.done {
		if m.err != "" {
			b.WriteString(styles.ErrorStyle.Render(fmt.Sprintf("Scan failed: %s", m.err)))
		} else {
			b.WriteString(fmt.Sprintf("Scan complete! Found %d findings.\n",
				len(m.result.Findings)))
		}
	} else {
		b.WriteString(fmt.Sprintf("%s Running %s scanner...\n",
			m.spinner.View(),
			styles.SelectedStyle.Render(m.scanner.Name())))
		b.WriteString(fmt.Sprintf("  Target: %s\n", targetDisplay(m.target)))
	}

	b.WriteString("\n")
	b.WriteString(styles.HelpStyle.Render("ctrl+c quit"))

	return b.String()
}

func (m ScanModel) runScan() tea.Cmd {
	s := m.scanner
	t := m.target
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), scanner.DefaultOptions().Timeout*100)
		defer cancel()

		opts := scanner.DefaultOptions()
		result, err := s.Run(ctx, t, opts)
		if err != nil {
			return scanErrorMsg{err: err}
		}
		return ScanCompleteMsg{Result: *result}
	}
}

func targetDisplay(t types.Target) string {
	if t.URL != "" {
		return t.URL
	}
	return t.Host
}
