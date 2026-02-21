package jobs

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/pkg/types"
)

// newUUID generates a simple UUID v4. Extracted as a variable for testing.
var newUUID = defaultNewUUID

func defaultNewUUID() string {
	// Simple timestamp+counter based ID — good enough for in-memory use.
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// Manager manages scan job lifecycle: create, execute, track, store results.
type Manager struct {
	mu     sync.RWMutex
	jobs   map[string]*Job
	runner *scanner.Runner
}

// NewManager creates a new job manager backed by the given scanner runner.
func NewManager(runner *scanner.Runner) *Manager {
	return &Manager{
		jobs:   make(map[string]*Job),
		runner: runner,
	}
}

// Create creates a new pending scan job.
func (m *Manager) Create(target types.Target, scanners []string, opts scanner.Options) *Job {
	m.mu.Lock()
	defer m.mu.Unlock()

	job := &Job{
		ID:        newUUID(),
		Target:    target,
		Scanners:  scanners,
		Options:   opts,
		Status:    StatusPending,
		CreatedAt: time.Now(),
		Progress: JobProgress{
			TotalScanners: len(scanners),
		},
	}
	m.jobs[job.ID] = job
	return job
}

// Start launches the scan job in a background goroutine.
func (m *Manager) Start(jobID string) error {
	m.mu.Lock()
	job, ok := m.jobs[jobID]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("job %q not found", jobID)
	}
	job.Status = StatusRunning
	job.StartedAt = time.Now()
	m.mu.Unlock()

	go m.execute(job)
	return nil
}

func (m *Manager) execute(job *Job) {
	defer func() {
		if r := recover(); r != nil {
			m.mu.Lock()
			job.Status = StatusFailed
			job.Error = fmt.Sprintf("panic: %v", r)
			job.CompletedAt = time.Now()
			m.mu.Unlock()
		}
	}()

	ctx := context.Background()
	if job.Options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, job.Options.Timeout*time.Duration(len(job.Scanners)+1))
		defer cancel()
	}

	for _, name := range job.Scanners {
		m.mu.Lock()
		job.Progress.CurrentScanner = name
		m.mu.Unlock()

		result, err := m.runner.RunOne(ctx, name, job.Target, job.Options)

		m.mu.Lock()
		if err != nil {
			job.Results = append(job.Results, types.ScanResult{
				ScannerName: name,
				Target:      job.Target,
				Error:       err.Error(),
			})
		} else if result != nil {
			job.Results = append(job.Results, *result)
		}
		job.Progress.CompletedScanners++
		m.mu.Unlock()
	}

	m.mu.Lock()
	job.Status = StatusCompleted
	job.CompletedAt = time.Now()
	job.Progress.CurrentScanner = ""
	m.mu.Unlock()
}

// Get returns a job by ID.
func (m *Manager) Get(jobID string) (*Job, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	job, ok := m.jobs[jobID]
	if !ok {
		return nil, fmt.Errorf("job %q not found", jobID)
	}
	return job, nil
}

// List returns all jobs sorted by CreatedAt descending.
func (m *Manager) List() []*Job {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Job, 0, len(m.jobs))
	for _, j := range m.jobs {
		result = append(result, j)
	}
	sort.Slice(result, func(i, k int) bool {
		return result[i].CreatedAt.After(result[k].CreatedAt)
	})
	return result
}

// Delete removes a job from the manager.
func (m *Manager) Delete(jobID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.jobs[jobID]; !ok {
		return fmt.Errorf("job %q not found", jobID)
	}
	delete(m.jobs, jobID)
	return nil
}

// Names returns all registered scanner names from the runner's registry.
func (m *Manager) Names() []string {
	// Delegate to the runner — but Runner doesn't expose registry names directly.
	// This will be wired up via the registry in integration.
	return nil
}
