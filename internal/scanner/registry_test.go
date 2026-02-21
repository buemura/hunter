package scanner

import (
	"context"
	"testing"

	"github.com/buemura/hunter/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockScanner struct {
	name string
}

func (m *mockScanner) Name() string        { return m.name }
func (m *mockScanner) Description() string { return "mock scanner" }
func (m *mockScanner) Run(_ context.Context, target types.Target, _ Options) (*types.ScanResult, error) {
	return &types.ScanResult{
		ScannerName: m.name,
		Target:      target,
		Findings: []types.Finding{
			{Title: "mock finding", Severity: types.SeverityInfo},
		},
	}, nil
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()
	s := &mockScanner{name: "test"}
	r.Register(s)

	got, err := r.Get("test")
	require.NoError(t, err)
	assert.Equal(t, s, got)
}

func TestRegistry_GetNotFound(t *testing.T) {
	r := NewRegistry()
	_, err := r.Get("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRegistry_All(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockScanner{name: "a"})
	r.Register(&mockScanner{name: "b"})

	all := r.All()
	assert.Len(t, all, 2)
}
