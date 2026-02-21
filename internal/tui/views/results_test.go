package views

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"

	"github.com/buemura/hunter/pkg/types"
)

func newTestResults() []types.ScanResult {
	return []types.ScanResult{
		{
			ScannerName: "port",
			Findings: []types.Finding{
				{Title: "Open port: 80", Severity: types.SeverityInfo, Description: "Port 80 is open"},
				{Title: "Open port: 443", Severity: types.SeverityInfo, Description: "Port 443 is open"},
			},
		},
		{
			ScannerName: "headers",
			Findings: []types.Finding{
				{Title: "Missing CSP header", Severity: types.SeverityMedium, Description: "No CSP header"},
				{Title: "Missing HSTS", Severity: types.SeverityHigh, Description: "No HSTS", Remediation: "Add HSTS header"},
			},
		},
	}
}

func TestResultsModelView(t *testing.T) {
	m := NewResultsModel(newTestResults())
	view := m.View()

	assert.Contains(t, view, "Scan Results")
	assert.Contains(t, view, "Open port: 80")
	assert.Contains(t, view, "Missing CSP header")
	assert.Contains(t, view, "Total: 4 findings")
}

func TestResultsModelNavigate(t *testing.T) {
	m := NewResultsModel(newTestResults())

	// Move down.
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	m = updated.(ResultsModel)
	assert.Equal(t, 1, m.cursor)

	// Move up.
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
	m = updated.(ResultsModel)
	assert.Equal(t, 0, m.cursor)

	// Should not go below 0.
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
	m = updated.(ResultsModel)
	assert.Equal(t, 0, m.cursor)
}

func TestResultsModelNavigateBoundary(t *testing.T) {
	results := []types.ScanResult{
		{
			ScannerName: "test",
			Findings: []types.Finding{
				{Title: "f1", Severity: types.SeverityInfo},
				{Title: "f2", Severity: types.SeverityLow},
			},
		},
	}
	m := NewResultsModel(results)

	// Navigate to last item.
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	m = updated.(ResultsModel)
	assert.Equal(t, 1, m.cursor)

	// Should not exceed bounds.
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	m = updated.(ResultsModel)
	assert.Equal(t, 1, m.cursor)
}

func TestResultsModelEmptyFindings(t *testing.T) {
	m := NewResultsModel([]types.ScanResult{
		{ScannerName: "test", Findings: nil},
	})
	view := m.View()
	assert.Contains(t, view, "No findings")
}

func TestResultsModelDetailViewIncludesRemediation(t *testing.T) {
	m := NewResultsModel(newTestResults())

	// Navigate to finding with remediation (index 3: Missing HSTS).
	for i := 0; i < 3; i++ {
		updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
		m = updated.(ResultsModel)
	}

	view := m.View()
	assert.Contains(t, view, "Remediation")
	assert.Contains(t, view, "Add HSTS header")
}

func TestResultsModelQuit(t *testing.T) {
	m := NewResultsModel(newTestResults())
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	assert.NotNil(t, cmd)
}

func TestTruncate(t *testing.T) {
	assert.Equal(t, "hello", truncate("hello", 10))
	assert.Equal(t, "hel...", truncate("hello world", 6))
	assert.Equal(t, "hello world", truncate("hello world", 50))
}
