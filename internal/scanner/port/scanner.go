package port

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/pkg/types"
)

// Scanner performs TCP connect scans to discover open ports.
type Scanner struct{}

func New() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Name() string        { return "port" }
func (s *Scanner) Description() string { return "TCP port scanner" }

func (s *Scanner) Run(ctx context.Context, target types.Target, opts scanner.Options) (*types.ScanResult, error) {
	result := &types.ScanResult{
		ScannerName: s.Name(),
		Target:      target,
		StartedAt:   time.Now(),
	}

	ports, err := resolvePorts(target, opts)
	if err != nil {
		return nil, fmt.Errorf("resolving ports: %w", err)
	}

	concurrency := opts.Concurrency
	if concurrency < 1 {
		concurrency = 10
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}

	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range ports {
		select {
		case <-ctx.Done():
			result.CompletedAt = time.Now()
			return result, nil
		default:
		}

		wg.Add(1)
		go func(port int) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			addr := net.JoinHostPort(target.Host, strconv.Itoa(port))
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err != nil {
				return
			}
			conn.Close()

			svc := IdentifyService(port)
			finding := types.Finding{
				Title:       fmt.Sprintf("Open port: %d/%s", port, svc),
				Description: fmt.Sprintf("TCP port %d is open (%s)", port, svc),
				Severity:    types.SeverityInfo,
				Metadata: map[string]string{
					"port":     strconv.Itoa(port),
					"protocol": "tcp",
					"service":  svc,
				},
			}

			mu.Lock()
			result.Findings = append(result.Findings, finding)
			mu.Unlock()
		}(p)
	}

	wg.Wait()
	result.CompletedAt = time.Now()
	return result, nil
}

func resolvePorts(target types.Target, opts scanner.Options) ([]int, error) {
	// Check ExtraArgs for port specification.
	if opts.ExtraArgs != nil {
		if spec, ok := opts.ExtraArgs["ports"].(string); ok && spec != "" {
			return ParsePortRange(spec)
		}
	}

	// Use ports from target if specified.
	if len(target.Ports) > 0 {
		return target.Ports, nil
	}

	return CommonPorts, nil
}
