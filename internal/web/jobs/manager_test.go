package jobs

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockScanner struct {
	name  string
	delay time.Duration
}

func (m *mockScanner) Name() string        { return m.name }
func (m *mockScanner) Description() string { return "mock" }
func (m *mockScanner) Run(_ context.Context, target types.Target, _ scanner.Options) (*types.ScanResult, error) {
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	return &types.ScanResult{
		ScannerName: m.name,
		Target:      target,
		Findings: []types.Finding{
			{Title: m.name + " finding", Severity: types.SeverityInfo},
		},
	}, nil
}

func newTestManager(scannerNames ...string) *Manager {
	reg := scanner.NewRegistry()
	for _, name := range scannerNames {
		reg.Register(&mockScanner{name: name})
	}
	runner := scanner.NewRunner(reg)
	return NewManager(runner)
}

func TestCreate_ReturnsPendingJob(t *testing.T) {
	m := newTestManager("headers")
	target := types.Target{Host: "example.com", Scheme: "https"}

	job := m.Create(target, []string{"headers"}, scanner.DefaultOptions())

	assert.NotEmpty(t, job.ID)
	assert.Equal(t, StatusPending, job.Status)
	assert.Equal(t, target, job.Target)
	assert.Equal(t, []string{"headers"}, job.Scanners)
	assert.False(t, job.CreatedAt.IsZero())
}

func TestStartAndComplete(t *testing.T) {
	m := newTestManager("headers")
	target := types.Target{Host: "example.com", Scheme: "https"}

	job := m.Create(target, []string{"headers"}, scanner.DefaultOptions())
	err := m.Start(job.ID)
	require.NoError(t, err)

	// Wait for completion.
	assert.Eventually(t, func() bool {
		m.mu.RLock()
		defer m.mu.RUnlock()
		return job.Status == StatusCompleted
	}, 5*time.Second, 10*time.Millisecond)

	assert.Equal(t, StatusCompleted, job.Status)
	assert.Len(t, job.Results, 1)
	assert.Equal(t, "headers", job.Results[0].ScannerName)
	assert.False(t, job.CompletedAt.IsZero())
}

func TestProgressUpdates(t *testing.T) {
	m := newTestManager("a", "b", "c")
	target := types.Target{Host: "example.com", Scheme: "https"}

	job := m.Create(target, []string{"a", "b", "c"}, scanner.DefaultOptions())
	err := m.Start(job.ID)
	require.NoError(t, err)

	assert.Eventually(t, func() bool {
		m.mu.RLock()
		defer m.mu.RUnlock()
		return job.Status == StatusCompleted
	}, 5*time.Second, 10*time.Millisecond)

	assert.Equal(t, 3, job.Progress.TotalScanners)
	assert.Equal(t, 3, job.Progress.CompletedScanners)
	assert.Empty(t, job.Progress.CurrentScanner)
}

func TestGet_ReturnsJob(t *testing.T) {
	m := newTestManager("headers")
	target := types.Target{Host: "example.com", Scheme: "https"}
	job := m.Create(target, []string{"headers"}, scanner.DefaultOptions())

	got, err := m.Get(job.ID)
	require.NoError(t, err)
	assert.Equal(t, job.ID, got.ID)
}

func TestGet_NotFound(t *testing.T) {
	m := newTestManager()
	_, err := m.Get("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestList_SortedByCreatedAtDesc(t *testing.T) {
	m := newTestManager("headers")
	target := types.Target{Host: "example.com", Scheme: "https"}

	// Override UUID generator for deterministic IDs.
	counter := 0
	origUUID := newUUID
	newUUID = func() string {
		counter++
		return fmt.Sprintf("job-%d", counter)
	}
	defer func() { newUUID = origUUID }()

	j1 := m.Create(target, []string{"headers"}, scanner.DefaultOptions())
	time.Sleep(time.Millisecond)
	j2 := m.Create(target, []string{"headers"}, scanner.DefaultOptions())

	list := m.List()
	require.Len(t, list, 2)
	assert.Equal(t, j2.ID, list[0].ID) // most recent first
	assert.Equal(t, j1.ID, list[1].ID)
}

func TestDelete_RemovesJob(t *testing.T) {
	m := newTestManager("headers")
	target := types.Target{Host: "example.com", Scheme: "https"}
	job := m.Create(target, []string{"headers"}, scanner.DefaultOptions())

	err := m.Delete(job.ID)
	require.NoError(t, err)

	_, err = m.Get(job.ID)
	assert.Error(t, err)
}

func TestDelete_NotFound(t *testing.T) {
	m := newTestManager()
	err := m.Delete("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestStart_InvalidJobID(t *testing.T) {
	m := newTestManager()
	err := m.Start("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestFindingCount(t *testing.T) {
	job := &Job{
		Results: []types.ScanResult{
			{Findings: []types.Finding{{Title: "a"}, {Title: "b"}}},
			{Findings: []types.Finding{{Title: "c"}}},
		},
	}
	assert.Equal(t, 3, job.FindingCount())
}
