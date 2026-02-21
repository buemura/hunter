package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/buemura/hunter/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestRunner_RunAll(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&mockScanner{name: "s1"})
	reg.Register(&mockScanner{name: "s2"})

	runner := NewRunner(reg)
	target := types.Target{Host: "localhost", Scheme: "https"}
	opts := Options{Concurrency: 2, Timeout: 5 * time.Second}

	results := runner.RunAll(context.Background(), []string{"s1", "s2"}, target, opts)
	assert.Len(t, results, 2)

	names := make(map[string]bool)
	for _, r := range results {
		names[r.ScannerName] = true
		assert.NotEmpty(t, r.Findings)
	}
	assert.True(t, names["s1"])
	assert.True(t, names["s2"])
}

func TestRunner_RunAll_UnknownScanner(t *testing.T) {
	reg := NewRegistry()
	runner := NewRunner(reg)
	target := types.Target{Host: "localhost", Scheme: "https"}

	results := runner.RunAll(context.Background(), []string{"unknown"}, target, DefaultOptions())
	assert.Len(t, results, 1)
	assert.Contains(t, results[0].Error, "not found")
}

func TestRunner_RunAll_ContextCancellation(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&slowScanner{name: "slow", delay: 2 * time.Second})

	runner := NewRunner(reg)
	target := types.Target{Host: "localhost", Scheme: "https"}
	opts := Options{Concurrency: 1, Timeout: 5 * time.Second}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	results := runner.RunAll(ctx, []string{"slow"}, target, opts)
	assert.Len(t, results, 1)
}

func TestRunner_RunOne(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&mockScanner{name: "test"})

	runner := NewRunner(reg)
	target := types.Target{Host: "localhost", Scheme: "https"}

	result, err := runner.RunOne(context.Background(), "test", target, DefaultOptions())
	assert.NoError(t, err)
	assert.Equal(t, "test", result.ScannerName)
}

func TestRunner_RunOne_NotFound(t *testing.T) {
	reg := NewRegistry()
	runner := NewRunner(reg)
	target := types.Target{Host: "localhost", Scheme: "https"}

	_, err := runner.RunOne(context.Background(), "nope", target, DefaultOptions())
	assert.Error(t, err)
}

type slowScanner struct {
	name  string
	delay time.Duration
}

func (s *slowScanner) Name() string        { return s.name }
func (s *slowScanner) Description() string { return "slow mock" }
func (s *slowScanner) Run(ctx context.Context, target types.Target, _ Options) (*types.ScanResult, error) {
	select {
	case <-time.After(s.delay):
		return &types.ScanResult{ScannerName: s.name, Target: target}, nil
	case <-ctx.Done():
		return &types.ScanResult{ScannerName: s.name, Target: target, Error: ctx.Err().Error()}, nil
	}
}
