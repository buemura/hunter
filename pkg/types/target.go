package types

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Target represents what to scan.
type Target struct {
	Host   string `json:"host"`
	Ports  []int  `json:"ports,omitempty"`
	URL    string `json:"url,omitempty"`
	Scheme string `json:"scheme"`
}

// ParseTarget accepts a host, host:port, or full URL and normalizes it into a Target.
func ParseTarget(raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Target{}, fmt.Errorf("target cannot be empty")
	}

	// If it looks like a URL (has a scheme), parse as URL.
	if strings.Contains(raw, "://") {
		return parseURL(raw)
	}

	// Try host:port format.
	host, portStr, err := net.SplitHostPort(raw)
	if err == nil {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return Target{}, fmt.Errorf("invalid port %q: %w", portStr, err)
		}
		if port < 1 || port > 65535 {
			return Target{}, fmt.Errorf("port %d out of range (1-65535)", port)
		}
		return Target{
			Host:   host,
			Ports:  []int{port},
			Scheme: "https",
		}, nil
	}

	// Plain hostname or IP.
	return Target{
		Host:   raw,
		Scheme: "https",
	}, nil
}

func parseURL(raw string) (Target, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Target{}, fmt.Errorf("invalid URL %q: %w", raw, err)
	}

	if u.Hostname() == "" {
		return Target{}, fmt.Errorf("URL %q has no hostname", raw)
	}

	t := Target{
		Host:   u.Hostname(),
		URL:    raw,
		Scheme: u.Scheme,
	}

	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil {
			return Target{}, fmt.Errorf("invalid port in URL: %w", err)
		}
		t.Ports = []int{port}
	}

	return t, nil
}
