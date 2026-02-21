package views

import (
	"fmt"
	"strings"

	"github.com/buemura/hunter/internal/tui/styles"
	"github.com/buemura/hunter/pkg/types"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// TargetModel is the view model for target URL/host input.
type TargetModel struct {
	textInput   textinput.Model
	scannerName string
	err         string
}

// NewTargetModel creates a new target input view.
func NewTargetModel() TargetModel {
	ti := textinput.New()
	ti.Placeholder = "e.g. https://example.com or 192.168.1.1"
	ti.Focus()
	ti.CharLimit = 256
	ti.Width = 50
	ti.PromptStyle = styles.CursorStyle
	ti.TextStyle = styles.SelectedStyle

	return TargetModel{textInput: ti}
}

// SetScannerName sets which scanner this target is for.
func (m *TargetModel) SetScannerName(name string) {
	m.scannerName = name
}

// ScannerName returns the selected scanner name.
func (m TargetModel) ScannerName() string {
	return m.scannerName
}

// Init returns the text input blink command.
func (m TargetModel) Init() tea.Cmd {
	return textinput.Blink
}

// Update handles input events.
func (m TargetModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok && keyMsg.String() == "enter" {
		_, err := types.ParseTarget(m.textInput.Value())
		if err != nil {
			m.err = err.Error()
			return m, nil
		}
		m.err = ""
		return m, nil
	}

	var cmd tea.Cmd
	m.textInput, cmd = m.textInput.Update(msg)
	m.err = ""
	return m, cmd
}

// View renders the target input form.
func (m TargetModel) View() string {
	var b strings.Builder

	b.WriteString(styles.TitleStyle.Render("Hunter — Interactive Mode"))
	b.WriteString("\n\n")
	b.WriteString(styles.HeaderStyle.Render(fmt.Sprintf("Scanner: %s", m.scannerName)))
	b.WriteString("\n")
	b.WriteString("Enter target URL or host:\n\n")
	b.WriteString(m.textInput.View())
	b.WriteString("\n")

	if m.err != "" {
		b.WriteString("\n")
		b.WriteString(styles.ErrorStyle.Render(m.err))
	}

	b.WriteString("\n")
	b.WriteString(styles.HelpStyle.Render("enter submit • esc back"))

	return b.String()
}

// ValidatedTarget parses and returns the target, or an error if invalid.
func (m TargetModel) ValidatedTarget() (types.Target, error) {
	value := strings.TrimSpace(m.textInput.Value())
	if value == "" {
		return types.Target{}, fmt.Errorf("target is required")
	}
	return types.ParseTarget(value)
}
