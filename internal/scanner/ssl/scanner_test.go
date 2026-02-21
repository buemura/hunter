package ssl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/buemura/hunter/internal/scanner"
	"github.com/buemura/hunter/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanner_NameAndDescription(t *testing.T) {
	s := New()
	assert.Equal(t, "ssl", s.Name())
	assert.Equal(t, "SSL/TLS configuration checks", s.Description())
}

// newTLSServer creates a TLS listener with the given certificate template.
// Returns the listener, its port, and a cleanup function.
func newTLSServer(t *testing.T, tmpl *x509.Certificate) (net.Listener, int) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	require.NoError(t, err)

	// Accept connections in background so TLS handshake completes.
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Perform TLS handshake before closing.
			if tlsConn, ok := conn.(*tls.Conn); ok {
				_ = tlsConn.Handshake()
			}
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return listener, port
}

func validCertTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
		BasicConstraintsValid: true,
	}
}

func TestScanner_ValidCert(t *testing.T) {
	tmpl := validCertTemplate()
	listener, port := newTLSServer(t, tmpl)
	defer listener.Close()

	s := New()
	target := types.Target{Host: "127.0.0.1", Ports: []int{port}, Scheme: "https"}
	opts := scanner.Options{Timeout: 3 * time.Second}

	result, err := s.Run(context.Background(), target, opts)
	require.NoError(t, err)
	assert.Empty(t, result.Error)

	// All findings should be INFO level (TLS version info) or self-signed MEDIUM.
	// No HIGH or CRITICAL findings expected for a valid (self-signed) cert with matching hostname.
	for _, f := range result.Findings {
		// Self-signed is expected since we use a self-signed cert, allow MEDIUM.
		if f.Title == "Self-signed certificate" {
			assert.Equal(t, types.SeverityMedium, f.Severity)
			continue
		}
		assert.Equal(t, types.SeverityInfo, f.Severity, "unexpected non-INFO finding: %s", f.Title)
	}
}

func TestScanner_ExpiredCert(t *testing.T) {
	tmpl := validCertTemplate()
	tmpl.NotBefore = time.Now().Add(-48 * time.Hour)
	tmpl.NotAfter = time.Now().Add(-24 * time.Hour) // Expired yesterday.

	listener, port := newTLSServer(t, tmpl)
	defer listener.Close()

	s := New()
	target := types.Target{Host: "127.0.0.1", Ports: []int{port}, Scheme: "https"}
	opts := scanner.Options{Timeout: 3 * time.Second}

	result, err := s.Run(context.Background(), target, opts)
	require.NoError(t, err)

	var foundExpired bool
	for _, f := range result.Findings {
		if f.Title == "Certificate expired" {
			foundExpired = true
			assert.Equal(t, types.SeverityHigh, f.Severity)
		}
	}
	assert.True(t, foundExpired, "expected to find an expired certificate finding")
}

func TestScanner_HostnameMismatch(t *testing.T) {
	tmpl := validCertTemplate()
	tmpl.Subject.CommonName = "other.example.com"
	tmpl.DNSNames = []string{"other.example.com"}
	tmpl.IPAddresses = nil // Remove IP SAN so it doesn't match 127.0.0.1.

	listener, port := newTLSServer(t, tmpl)
	defer listener.Close()

	s := New()
	target := types.Target{Host: "127.0.0.1", Ports: []int{port}, Scheme: "https"}
	opts := scanner.Options{Timeout: 3 * time.Second}

	result, err := s.Run(context.Background(), target, opts)
	require.NoError(t, err)

	var foundMismatch bool
	for _, f := range result.Findings {
		if f.Title == "Certificate hostname mismatch" {
			foundMismatch = true
			assert.Equal(t, types.SeverityHigh, f.Severity)
		}
	}
	assert.True(t, foundMismatch, "expected to find a hostname mismatch finding")
}

func TestScanner_ConnectionRefused(t *testing.T) {
	// Use a port that is almost certainly not listening.
	s := New()
	target := types.Target{Host: "127.0.0.1", Ports: []int{39999}, Scheme: "https"}
	opts := scanner.Options{Timeout: 1 * time.Second}

	result, err := s.Run(context.Background(), target, opts)
	require.NoError(t, err) // Should not panic or return error.
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.Error) // Connection failure recorded in result.Error.
}

func TestScanner_ExpiringCert(t *testing.T) {
	tmpl := validCertTemplate()
	tmpl.NotAfter = time.Now().Add(15 * 24 * time.Hour) // Expires in 15 days.

	listener, port := newTLSServer(t, tmpl)
	defer listener.Close()

	s := New()
	target := types.Target{Host: "127.0.0.1", Ports: []int{port}, Scheme: "https"}
	opts := scanner.Options{Timeout: 3 * time.Second}

	result, err := s.Run(context.Background(), target, opts)
	require.NoError(t, err)

	var foundExpiring bool
	for _, f := range result.Findings {
		if f.Severity == types.SeverityMedium && f.Metadata["days_until_expiry"] != "" {
			foundExpiring = true
		}
	}
	assert.True(t, foundExpiring, "expected to find a certificate expiring soon finding")
}

func TestScanner_DefaultPort(t *testing.T) {
	target := types.Target{Host: "127.0.0.1", Scheme: "https"}
	assert.Equal(t, 443, resolvePort(target))
}

func TestScanner_CustomPort(t *testing.T) {
	target := types.Target{Host: "127.0.0.1", Ports: []int{8443}, Scheme: "https"}
	assert.Equal(t, 8443, resolvePort(target))
}
