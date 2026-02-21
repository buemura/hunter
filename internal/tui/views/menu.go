package views

import (
	"fmt"
	"strings"

	"github.com/buemura/hunter/internal/tui/styles"
	tea "github.com/charmbracelet/bubbletea"
)

// ScannerItem represents a scanner available in the menu.
type ScannerItem struct {
	Name        string
	Description string
}

// MenuModel is the view model for the scanner selection menu.
type MenuModel struct {
	items  []ScannerItem
	cursor int
}

// NewMenuModel creates a menu with the given scanner items.
func NewMenuModel(items []ScannerItem) MenuModel {
	return MenuModel{items: items}
}

// Init returns nil (no initial command).
func (m MenuModel) Init() tea.Cmd {
	return nil
}

// Update handles key navigation in the menu.
func (m MenuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.items)-1 {
				m.cursor++
			}
		case "q":
			return m, tea.Quit
		}
	}
	return m, nil
}

// View renders the scanner selection menu.
func (m MenuModel) View() string {
	var b strings.Builder

	b.WriteString(styles.TitleStyle.Render("Hunter — Interactive Mode"))
	b.WriteString("\n\n")
	b.WriteString(styles.HeaderStyle.Render("Select a scan type:"))
	b.WriteString("\n")

	for i, item := range m.items {
		cursor := "  "
		nameStyle := styles.HelpStyle
		if i == m.cursor {
			cursor = styles.CursorStyle.Render("> ")
			nameStyle = styles.SelectedStyle
		}

		b.WriteString(fmt.Sprintf("%s%s  %s\n",
			cursor,
			nameStyle.Render(item.Name),
			styles.HelpStyle.Render(item.Description),
		))
	}

	b.WriteString("\n")
	b.WriteString(styles.HelpStyle.Render("↑/↓ navigate • enter select • q quit"))

	return b.String()
}

// Selected returns the currently highlighted scanner item, or nil if empty.
func (m MenuModel) Selected() *ScannerItem {
	if len(m.items) == 0 {
		return nil
	}
	return &m.items[m.cursor]
}

// Cursor returns the current cursor position.
func (m MenuModel) Cursor() int {
	return m.cursor
}

// Items returns the menu items.
func (m MenuModel) Items() []ScannerItem {
	return m.items
}
