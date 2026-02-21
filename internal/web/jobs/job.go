package jobs

import (
	"time"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/pkg/types"
)

// JobStatus represents the current state of a scan job.
type JobStatus string

const (
	StatusPending   JobStatus = "pending"
	StatusRunning   JobStatus = "running"
	StatusCompleted JobStatus = "completed"
	StatusFailed    JobStatus = "failed"
)

// JobProgress tracks scanner-level progress within a job.
type JobProgress struct {
	TotalScanners     int    `json:"total_scanners"`
	CompletedScanners int    `json:"completed_scanners"`
	CurrentScanner    string `json:"current_scanner"`
}

// Job represents an async scan job.
type Job struct {
	ID          string             `json:"id"`
	Target      types.Target       `json:"target"`
	Scanners    []string           `json:"scanners"`
	Options     scanner.Options    `json:"-"`
	Status      JobStatus          `json:"status"`
	Results     []types.ScanResult `json:"results,omitempty"`
	Error       string             `json:"error,omitempty"`
	CreatedAt   time.Time          `json:"created_at"`
	StartedAt   time.Time          `json:"started_at,omitempty"`
	CompletedAt time.Time          `json:"completed_at,omitempty"`
	Progress    JobProgress        `json:"progress"`
}

// FindingCount returns the total number of findings across all results.
func (j *Job) FindingCount() int {
	n := 0
	for _, r := range j.Results {
		n += len(r.Findings)
	}
	return n
}
