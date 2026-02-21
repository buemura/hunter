package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// CreateScanRequest is the JSON body for POST /api/v1/scans.
type CreateScanRequest struct {
	Target      string   `json:"target"`
	Scanners    []string `json:"scanners"`
	Concurrency int      `json:"concurrency"`
	Timeout     string   `json:"timeout"`
}

// decodeCreateScanRequest reads and validates the request body.
func decodeCreateScanRequest(r *http.Request) (*CreateScanRequest, error) {
	var req CreateScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	if req.Target == "" {
		return nil, fmt.Errorf("target is required")
	}

	if req.Concurrency < 0 {
		return nil, fmt.Errorf("concurrency must be non-negative")
	}
	if req.Concurrency == 0 {
		req.Concurrency = 10
	}

	if req.Timeout != "" {
		if _, err := time.ParseDuration(req.Timeout); err != nil {
			return nil, fmt.Errorf("invalid timeout %q: %w", req.Timeout, err)
		}
	}

	return &req, nil
}
