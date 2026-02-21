package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTarget_PlainHost(t *testing.T) {
	target, err := ParseTarget("example.com")
	require.NoError(t, err)
	assert.Equal(t, "example.com", target.Host)
	assert.Equal(t, "https", target.Scheme)
	assert.Empty(t, target.Ports)
	assert.Empty(t, target.URL)
}

func TestParseTarget_HostPort(t *testing.T) {
	target, err := ParseTarget("192.168.1.1:8080")
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.1", target.Host)
	assert.Equal(t, []int{8080}, target.Ports)
	assert.Equal(t, "https", target.Scheme)
}

func TestParseTarget_HTTPURL(t *testing.T) {
	target, err := ParseTarget("http://example.com/path")
	require.NoError(t, err)
	assert.Equal(t, "example.com", target.Host)
	assert.Equal(t, "http", target.Scheme)
	assert.Equal(t, "http://example.com/path", target.URL)
	assert.Empty(t, target.Ports)
}

func TestParseTarget_HTTPSURLWithPort(t *testing.T) {
	target, err := ParseTarget("https://example.com:9443/api")
	require.NoError(t, err)
	assert.Equal(t, "example.com", target.Host)
	assert.Equal(t, "https", target.Scheme)
	assert.Equal(t, []int{9443}, target.Ports)
	assert.Equal(t, "https://example.com:9443/api", target.URL)
}

func TestParseTarget_IPAddress(t *testing.T) {
	target, err := ParseTarget("10.0.0.1")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1", target.Host)
	assert.Equal(t, "https", target.Scheme)
}

func TestParseTarget_Empty(t *testing.T) {
	_, err := ParseTarget("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestParseTarget_Whitespace(t *testing.T) {
	target, err := ParseTarget("  example.com  ")
	require.NoError(t, err)
	assert.Equal(t, "example.com", target.Host)
}

func TestParseTarget_InvalidPort(t *testing.T) {
	_, err := ParseTarget("example.com:abc")
	assert.Error(t, err)
}

func TestParseTarget_PortOutOfRange(t *testing.T) {
	_, err := ParseTarget("example.com:99999")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
}

func TestSeverityRank(t *testing.T) {
	assert.Less(t, SeverityRank(SeverityCritical), SeverityRank(SeverityHigh))
	assert.Less(t, SeverityRank(SeverityHigh), SeverityRank(SeverityMedium))
	assert.Less(t, SeverityRank(SeverityMedium), SeverityRank(SeverityLow))
	assert.Less(t, SeverityRank(SeverityLow), SeverityRank(SeverityInfo))
}
