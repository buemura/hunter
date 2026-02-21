package views

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewTargetModel(t *testing.T) {
	m := NewTargetModel()
	assert.Equal(t, "", m.ScannerName())
}

func TestTargetModelSetScannerName(t *testing.T) {
	m := NewTargetModel()
	m.SetScannerName("port")
	assert.Equal(t, "port", m.ScannerName())
}

func TestTargetModelView(t *testing.T) {
	m := NewTargetModel()
	m.SetScannerName("headers")
	view := m.View()

	assert.Contains(t, view, "Hunter")
	assert.Contains(t, view, "headers")
	assert.Contains(t, view, "Enter target")
	assert.Contains(t, view, "esc back")
}

func TestTargetModelValidatedTargetEmpty(t *testing.T) {
	m := NewTargetModel()
	_, err := m.ValidatedTarget()
	assert.Error(t, err)
}

func TestTargetModelInit(t *testing.T) {
	m := NewTargetModel()
	cmd := m.Init()
	assert.NotNil(t, cmd)
}
