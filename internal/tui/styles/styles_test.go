package styles

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSeverityStyleReturnsCritical(t *testing.T) {
	s := SeverityStyle("CRITICAL")
	rendered := s.Render("test")
	assert.Contains(t, rendered, "test")
}

func TestSeverityStyleReturnsHigh(t *testing.T) {
	s := SeverityStyle("HIGH")
	rendered := s.Render("test")
	assert.Contains(t, rendered, "test")
}

func TestSeverityStyleReturnsMedium(t *testing.T) {
	s := SeverityStyle("MEDIUM")
	rendered := s.Render("test")
	assert.Contains(t, rendered, "test")
}

func TestSeverityStyleReturnsLow(t *testing.T) {
	s := SeverityStyle("LOW")
	rendered := s.Render("test")
	assert.Contains(t, rendered, "test")
}

func TestSeverityStyleReturnsInfo(t *testing.T) {
	s := SeverityStyle("INFO")
	rendered := s.Render("test")
	assert.Contains(t, rendered, "test")
}

func TestSeverityStyleReturnsDefaultForUnknown(t *testing.T) {
	s := SeverityStyle("UNKNOWN")
	rendered := s.Render("test")
	assert.Contains(t, rendered, "test")
}

func TestStylesRender(t *testing.T) {
	tests := []struct {
		name  string
		style func(...string) string
	}{
		{"TitleStyle", TitleStyle.Render},
		{"HeaderStyle", HeaderStyle.Render},
		{"BorderStyle", BorderStyle.Render},
		{"SelectedStyle", SelectedStyle.Render},
		{"CursorStyle", CursorStyle.Render},
		{"HelpStyle", HelpStyle.Render},
		{"ErrorStyle", ErrorStyle.Render},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.style("hello")
			assert.Contains(t, result, "hello")
		})
	}
}
