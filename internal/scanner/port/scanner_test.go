package port

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePortRange_Single(t *testing.T) {
	ports, err := ParsePortRange("80")
	require.NoError(t, err)
	assert.Equal(t, []int{80}, ports)
}

func TestParsePortRange_CommaSeparated(t *testing.T) {
	ports, err := ParsePortRange("80,443,8080")
	require.NoError(t, err)
	assert.Equal(t, []int{80, 443, 8080}, ports)
}

func TestParsePortRange_Range(t *testing.T) {
	ports, err := ParsePortRange("1-5")
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2, 3, 4, 5}, ports)
}

func TestParsePortRange_Common(t *testing.T) {
	ports, err := ParsePortRange("common")
	require.NoError(t, err)
	assert.Equal(t, CommonPorts, ports)
}

func TestParsePortRange_Empty(t *testing.T) {
	ports, err := ParsePortRange("")
	require.NoError(t, err)
	assert.Equal(t, CommonPorts, ports)
}

func TestParsePortRange_Invalid(t *testing.T) {
	_, err := ParsePortRange("abc")
	assert.Error(t, err)
}

func TestParsePortRange_InvalidRange(t *testing.T) {
	_, err := ParsePortRange("100-50")
	assert.Error(t, err)
}

func TestParsePortRange_OutOfBounds(t *testing.T) {
	_, err := ParsePortRange("0-100")
	assert.Error(t, err)
}

func TestIdentifyService(t *testing.T) {
	assert.Equal(t, "HTTP", IdentifyService(80))
	assert.Equal(t, "SSH", IdentifyService(22))
	assert.Equal(t, "unknown", IdentifyService(12345))
}

func TestScanner_DetectsOpenPort(t *testing.T) {
	// Start a local listener on a random port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	_, portStr, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	s := New()
	target := types.Target{Host: "127.0.0.1", Scheme: "https"}
	opts := scanner.Options{
		Concurrency: 5,
		Timeout:     2 * time.Second,
		ExtraArgs:   map[string]interface{}{"ports": portStr},
	}

	result, err := s.Run(context.Background(), target, opts)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, strconv.Itoa(port), result.Findings[0].Metadata["port"])
}

func TestScanner_ClosedPort(t *testing.T) {
	// Find a port that's almost certainly closed.
	s := New()
	target := types.Target{Host: "127.0.0.1", Scheme: "https"}
	opts := scanner.Options{
		Concurrency: 5,
		Timeout:     500 * time.Millisecond,
		ExtraArgs:   map[string]interface{}{"ports": "39999"},
	}

	result, err := s.Run(context.Background(), target, opts)
	require.NoError(t, err)
	assert.Empty(t, result.Findings)
}

func TestScanner_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	s := New()
	target := types.Target{Host: "127.0.0.1", Scheme: "https"}
	opts := scanner.Options{
		Concurrency: 5,
		Timeout:     2 * time.Second,
		ExtraArgs:   map[string]interface{}{"ports": "80,443"},
	}

	result, err := s.Run(ctx, target, opts)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestScanner_NameAndDescription(t *testing.T) {
	s := New()
	assert.Equal(t, "port", s.Name())
	assert.NotEmpty(t, s.Description())
}
