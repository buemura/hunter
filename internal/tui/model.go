package tui

import (
	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/internal/tui/views"
	"github.com/buemura/hunter/pkg/types"
	tea "github.com/charmbracelet/bubbletea"
)

// appState represents which view is currently active.
type appState int

const (
	stateMenu    appState = iota // Scanner selection menu
	stateTarget                  // Target URL/host input
	stateScan                    // Scan in progress
	stateResults                 // Results display
)

// Model is the root Bubble Tea model that manages view transitions.
type Model struct {
	state    appState
	registry *scanner.Registry
	width    int
	height   int

	// Sub-models for each view.
	menu    views.MenuModel
	target  views.TargetModel
	scan    views.ScanModel
	results views.ResultsModel
}

// NewModel creates a root model with the given scanner registry.
func NewModel(reg *scanner.Registry) Model {
	scanners := reg.All()
	items := make([]views.ScannerItem, len(scanners))
	for i, s := range scanners {
		items[i] = views.ScannerItem{
			Name:        s.Name(),
			Description: s.Description(),
		}
	}

	return Model{
		state:    stateMenu,
		registry: reg,
		menu:     views.NewMenuModel(items),
		target:   views.NewTargetModel(),
	}
}

// Init returns the initial command.
func (m Model) Init() tea.Cmd {
	return m.target.Init()
}

// Update handles messages and manages state transitions.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			return m.handleBack()
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	switch m.state {
	case stateMenu:
		return m.updateMenu(msg)
	case stateTarget:
		return m.updateTarget(msg)
	case stateScan:
		return m.updateScan(msg)
	case stateResults:
		return m.updateResults(msg)
	}

	return m, nil
}

// View renders the current view.
func (m Model) View() string {
	switch m.state {
	case stateMenu:
		return m.menu.View()
	case stateTarget:
		return m.target.View()
	case stateScan:
		return m.scan.View()
	case stateResults:
		return m.results.View()
	}
	return ""
}

func (m Model) handleBack() (tea.Model, tea.Cmd) {
	switch m.state {
	case stateTarget:
		m.state = stateMenu
		return m, nil
	case stateResults:
		m.state = stateMenu
		return m, nil
	}
	return m, nil
}

func (m Model) updateMenu(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok && keyMsg.String() == "enter" {
		selected := m.menu.Selected()
		if selected != nil {
			m.target = views.NewTargetModel()
			m.target.SetScannerName(selected.Name)
			m.state = stateTarget
			return m, m.target.Init()
		}
	}

	updated, cmd := m.menu.Update(msg)
	m.menu = updated.(views.MenuModel)
	return m, cmd
}

func (m Model) updateTarget(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok && keyMsg.String() == "enter" {
		target, err := m.target.ValidatedTarget()
		if err == nil {
			scannerName := m.target.ScannerName()
			s, sErr := m.registry.Get(scannerName)
			if sErr != nil {
				return m, nil
			}
			m.scan = views.NewScanModel(s, target)
			m.state = stateScan
			return m, m.scan.Init()
		}
	}

	updated, cmd := m.target.Update(msg)
	m.target = updated.(views.TargetModel)
	return m, cmd
}

func (m Model) updateScan(msg tea.Msg) (tea.Model, tea.Cmd) {
	if scanMsg, ok := msg.(views.ScanCompleteMsg); ok {
		m.results = views.NewResultsModel([]types.ScanResult{scanMsg.Result})
		m.state = stateResults
		return m, nil
	}

	updated, cmd := m.scan.Update(msg)
	m.scan = updated.(views.ScanModel)
	return m, cmd
}

func (m Model) updateResults(msg tea.Msg) (tea.Model, tea.Cmd) {
	updated, cmd := m.results.Update(msg)
	m.results = updated.(views.ResultsModel)
	return m, cmd
}
