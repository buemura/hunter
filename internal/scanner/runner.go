package scanner

import (
	"context"
	"sync"

	"github.com/buemura/hunter/pkg/types"
)

// Runner orchestrates concurrent scanner execution.
type Runner struct {
	registry *Registry
}

// NewRunner creates a runner backed by the given registry.
func NewRunner(registry *Registry) *Runner {
	return &Runner{registry: registry}
}

// RunAll executes the named scanners concurrently, bounded by opts.Concurrency.
func (r *Runner) RunAll(ctx context.Context, names []string, target types.Target, opts Options) []types.ScanResult {
	concurrency := opts.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}

	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var results []types.ScanResult
	var wg sync.WaitGroup

	for _, name := range names {
		s, err := r.registry.Get(name)
		if err != nil {
			results = append(results, types.ScanResult{
				ScannerName: name,
				Target:      target,
				Error:       err.Error(),
			})
			continue
		}

		wg.Add(1)
		go func(scanner Scanner) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				mu.Lock()
				results = append(results, types.ScanResult{
					ScannerName: scanner.Name(),
					Target:      target,
					Error:       ctx.Err().Error(),
				})
				mu.Unlock()
				return
			}

			result, err := scanner.Run(ctx, target, opts)
			mu.Lock()
			if err != nil {
				results = append(results, types.ScanResult{
					ScannerName: scanner.Name(),
					Target:      target,
					Error:       err.Error(),
				})
			} else if result != nil {
				results = append(results, *result)
			}
			mu.Unlock()
		}(s)
	}

	wg.Wait()
	return results
}

// RunOne executes a single scanner by name.
func (r *Runner) RunOne(ctx context.Context, name string, target types.Target, opts Options) (*types.ScanResult, error) {
	s, err := r.registry.Get(name)
	if err != nil {
		return nil, err
	}
	return s.Run(ctx, target, opts)
}
