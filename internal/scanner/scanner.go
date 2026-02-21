package scanner

import (
	"context"
	"time"

	"github.com/buemura/hunter/pkg/types"
)

// Scanner is the core interface every scan module implements.
type Scanner interface {
	Name() string
	Description() string
	Run(ctx context.Context, target types.Target, opts Options) (*types.ScanResult, error)
}

// Options holds scanner-wide execution parameters.
type Options struct {
	Concurrency int
	Timeout     time.Duration
	Verbose     bool
	ExtraArgs   map[string]interface{}
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Concurrency: 10,
		Timeout:     5 * time.Second,
	}
}
