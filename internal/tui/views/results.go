package views

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/buemura/hunter/internal/tui/styles"
	"github.com/buemura/hunter/pkg/types"
	tea "github.com/charmbracelet/bubbletea"
)

// ResultsModel is the view model for displaying scan results.
type ResultsModel struct {
	results  []types.ScanResult
	cursor   int
	offset   int
	maxRows  int
	exported bool
	exportErr string
}

// NewResultsModel creates a results view from scan results.
func NewResultsModel(results []types.ScanResult) ResultsModel {
	return ResultsModel{
		results: results,
		maxRows: 20,
	}
}

// Init returns nil (no initial command).
func (m ResultsModel) Init() tea.Cmd {
	return nil
}

// Update handles key events for scrolling and export.
func (m ResultsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	findings := m.allFindings()

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
				if m.cursor < m.offset {
					m.offset = m.cursor
				}
			}
		case "down", "j":
			if m.cursor < len(findings)-1 {
				m.cursor++
				if m.cursor >= m.offset+m.maxRows {
					m.offset = m.cursor - m.maxRows + 1
				}
			}
		case "e":
			m.exportJSON()
		case "q":
			return m, tea.Quit
		}
	}

	return m, nil
}

// View renders the results table.
func (m ResultsModel) View() string {
	var b strings.Builder

	b.WriteString(styles.TitleStyle.Render("Hunter — Scan Results"))
	b.WriteString("\n\n")

	findings := m.allFindings()
	if len(findings) == 0 {
		b.WriteString("No findings discovered.\n")
	} else {
		// Summary line.
		b.WriteString(m.summaryLine(findings))
		b.WriteString("\n\n")

		// Table header.
		header := fmt.Sprintf("  %-10s %-50s %s", "SEVERITY", "TITLE", "SCANNER")
		b.WriteString(styles.HeaderStyle.Render(header))
		b.WriteString("\n")
		b.WriteString(strings.Repeat("─", 80))
		b.WriteString("\n")

		// Table rows with scrolling.
		end := m.offset + m.maxRows
		if end > len(findings) {
			end = len(findings)
		}

		for i := m.offset; i < end; i++ {
			f := findings[i]
			cursor := "  "
			if i == m.cursor {
				cursor = styles.CursorStyle.Render("> ")
			}

			sevStyle := styles.SeverityStyle(string(f.finding.Severity))
			severity := sevStyle.Render(fmt.Sprintf("%-10s", f.finding.Severity))
			title := truncate(f.finding.Title, 50)
			scanner := styles.HelpStyle.Render(f.scannerName)

			b.WriteString(fmt.Sprintf("%s%s %-50s %s\n", cursor, severity, title, scanner))
		}

		// Scroll indicator.
		if len(findings) > m.maxRows {
			b.WriteString(fmt.Sprintf("\n  Showing %d-%d of %d findings\n",
				m.offset+1, end, len(findings)))
		}
	}

	// Detail view for selected finding.
	if len(findings) > 0 && m.cursor < len(findings) {
		b.WriteString("\n")
		b.WriteString(m.detailView(findings[m.cursor]))
	}

	if m.exported {
		b.WriteString("\n")
		b.WriteString(styles.SelectedStyle.Render("Results exported to hunter-results.json"))
	}
	if m.exportErr != "" {
		b.WriteString("\n")
		b.WriteString(styles.ErrorStyle.Render(m.exportErr))
	}

	b.WriteString("\n")
	b.WriteString(styles.HelpStyle.Render("↑/↓ scroll • e export JSON • esc back • q quit"))

	return b.String()
}

type findingRow struct {
	finding     types.Finding
	scannerName string
}

func (m ResultsModel) allFindings() []findingRow {
	var rows []findingRow
	for _, r := range m.results {
		for _, f := range r.Findings {
			rows = append(rows, findingRow{finding: f, scannerName: r.ScannerName})
		}
	}
	return rows
}

func (m ResultsModel) summaryLine(findings []findingRow) string {
	counts := map[types.Severity]int{}
	for _, f := range findings {
		counts[f.finding.Severity]++
	}

	parts := []string{}
	for _, sev := range []types.Severity{
		types.SeverityCritical, types.SeverityHigh,
		types.SeverityMedium, types.SeverityLow, types.SeverityInfo,
	} {
		if c, ok := counts[sev]; ok && c > 0 {
			style := styles.SeverityStyle(string(sev))
			parts = append(parts, style.Render(fmt.Sprintf("%s: %d", sev, c)))
		}
	}

	return fmt.Sprintf("Total: %d findings  [%s]", len(findings), strings.Join(parts, "  "))
}

func (m ResultsModel) detailView(row findingRow) string {
	var b strings.Builder
	b.WriteString(styles.BorderStyle.Render(
		fmt.Sprintf("Title: %s\nSeverity: %s\nDescription: %s",
			row.finding.Title,
			row.finding.Severity,
			row.finding.Description,
		),
	))

	if row.finding.Evidence != "" {
		b.WriteString(fmt.Sprintf("\n  Evidence: %s", row.finding.Evidence))
	}
	if row.finding.Remediation != "" {
		b.WriteString(fmt.Sprintf("\n  Remediation: %s", row.finding.Remediation))
	}

	return b.String()
}

func (m *ResultsModel) exportJSON() {
	data, err := json.MarshalIndent(m.results, "", "  ")
	if err != nil {
		m.exportErr = fmt.Sprintf("export failed: %v", err)
		return
	}

	if err := os.WriteFile("hunter-results.json", data, 0644); err != nil {
		m.exportErr = fmt.Sprintf("export failed: %v", err)
		return
	}

	m.exported = true
	m.exportErr = ""
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
