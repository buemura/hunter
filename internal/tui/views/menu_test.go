package views

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMenuModel(t *testing.T) {
	items := []ScannerItem{
		{Name: "port", Description: "TCP port scanner"},
		{Name: "headers", Description: "HTTP header scanner"},
	}
	m := NewMenuModel(items)

	assert.Equal(t, 0, m.Cursor())
	assert.Equal(t, 2, len(m.Items()))
}

func TestMenuModelNavigateDown(t *testing.T) {
	items := []ScannerItem{
		{Name: "port", Description: "TCP port scanner"},
		{Name: "headers", Description: "HTTP header scanner"},
		{Name: "ssl", Description: "SSL/TLS scanner"},
	}
	m := NewMenuModel(items)

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	m = updated.(MenuModel)
	assert.Equal(t, 1, m.Cursor())

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	m = updated.(MenuModel)
	assert.Equal(t, 2, m.Cursor())

	// Should not go past the end.
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	m = updated.(MenuModel)
	assert.Equal(t, 2, m.Cursor())
}

func TestMenuModelNavigateUp(t *testing.T) {
	items := []ScannerItem{
		{Name: "port", Description: "TCP port scanner"},
		{Name: "headers", Description: "HTTP header scanner"},
	}
	m := NewMenuModel(items)

	// Should not go below 0.
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
	m = updated.(MenuModel)
	assert.Equal(t, 0, m.Cursor())

	// Go down then up.
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	m = updated.(MenuModel)
	assert.Equal(t, 1, m.Cursor())

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
	m = updated.(MenuModel)
	assert.Equal(t, 0, m.Cursor())
}

func TestMenuModelSelected(t *testing.T) {
	items := []ScannerItem{
		{Name: "port", Description: "TCP port scanner"},
		{Name: "headers", Description: "HTTP header scanner"},
	}
	m := NewMenuModel(items)

	selected := m.Selected()
	require.NotNil(t, selected)
	assert.Equal(t, "port", selected.Name)

	// Move down and check selection changes.
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	m = updated.(MenuModel)
	selected = m.Selected()
	require.NotNil(t, selected)
	assert.Equal(t, "headers", selected.Name)
}

func TestMenuModelSelectedEmpty(t *testing.T) {
	m := NewMenuModel([]ScannerItem{})
	assert.Nil(t, m.Selected())
}

func TestMenuModelView(t *testing.T) {
	items := []ScannerItem{
		{Name: "port", Description: "TCP port scanner"},
	}
	m := NewMenuModel(items)
	view := m.View()

	assert.Contains(t, view, "Hunter")
	assert.Contains(t, view, "port")
	assert.Contains(t, view, "TCP port scanner")
	assert.Contains(t, view, "navigate")
}

func TestMenuModelQuit(t *testing.T) {
	m := NewMenuModel([]ScannerItem{{Name: "port", Description: "test"}})
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	require.NotNil(t, cmd)
}
