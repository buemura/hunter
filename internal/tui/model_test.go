package tui

import (
	"testing"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/internal/scanner/port"
	"github.com/buemura/hunter/internal/scanner/headers"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
)

func newTestRegistry() *scanner.Registry {
	reg := scanner.NewRegistry()
	reg.Register(port.New())
	reg.Register(headers.New())
	return reg
}

func TestNewModelStartsAtMenuState(t *testing.T) {
	m := NewModel(newTestRegistry())
	assert.Equal(t, stateMenu, m.state)
}

func TestNewModelPopulatesMenuItems(t *testing.T) {
	m := NewModel(newTestRegistry())
	items := m.menu.Items()
	assert.Equal(t, 2, len(items))
}

func TestModelViewRendersMenuByDefault(t *testing.T) {
	m := NewModel(newTestRegistry())
	view := m.View()
	assert.Contains(t, view, "Hunter")
	assert.Contains(t, view, "Select a scan type")
}

func TestModelCtrlCQuits(t *testing.T) {
	m := NewModel(newTestRegistry())
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	assert.NotNil(t, cmd)
}

func TestModelEscFromTargetReturnsToMenu(t *testing.T) {
	m := NewModel(newTestRegistry())
	m.state = stateTarget

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	model := updated.(Model)
	assert.Equal(t, stateMenu, model.state)
}

func TestModelEscFromResultsReturnsToMenu(t *testing.T) {
	m := NewModel(newTestRegistry())
	m.state = stateResults

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	model := updated.(Model)
	assert.Equal(t, stateMenu, model.state)
}

func TestModelWindowSizeMsg(t *testing.T) {
	m := NewModel(newTestRegistry())
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	model := updated.(Model)
	assert.Equal(t, 120, model.width)
	assert.Equal(t, 40, model.height)
}
