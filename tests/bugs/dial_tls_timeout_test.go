package tests

import (
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

func TestTLSDialing(t *testing.T) {
	// Test configuration
	testCases := []struct {
		name     string
		host     string
		port     string
		wantTLS  bool
		wantHTTP bool
	}{
		{
			name:     "GitHub HTTPS Port",
			host:     "github.com",
			port:     "443",
			wantTLS:  true,
			wantHTTP: false,
		},
		{
			name:     "GitHub HTTP Port",
			host:     "github.com",
			port:     "80",
			wantTLS:  false,
			wantHTTP: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new fasthttp dialer
			dialer := &fasthttp.TCPDialer{
				Concurrency:      2048,
				DNSCacheDuration: 10 * time.Minute,
			}

			addr := net.JoinHostPort(tc.host, tc.port)

			// Test TLS connection
			tlsOK := testTLSHandshake(t, dialer, addr)
			assert.Equal(t, tc.wantTLS, tlsOK, "TLS handshake result mismatch")

			// Test HTTP connection
			httpOK := testHTTPConnection(t, dialer, addr)
			assert.Equal(t, tc.wantHTTP, httpOK, "HTTP connection result mismatch")
		})
	}
}

func TestTLSDialing_IP(t *testing.T) {
	testCases := []struct {
		name     string
		domain   string // Original domain for resolution
		port     string
		wantTLS  bool
		wantHTTP bool
	}{
		{
			name:     "GitHub HTTPS Port",
			domain:   "github.com",
			port:     "443",
			wantTLS:  true,
			wantHTTP: false,
		},
		{
			name:     "GitHub HTTP Port",
			domain:   "github.com",
			port:     "80",
			wantTLS:  false,
			wantHTTP: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Resolve IP first
			ips, err := net.LookupIP(tc.domain)
			require.NoError(t, err, "IP lookup failed")
			require.NotEmpty(t, ips, "No IPs resolved")

			// Create dialer
			dialer := &fasthttp.TCPDialer{
				Concurrency:      2048,
				DNSCacheDuration: 10 * time.Minute,
			}

			// Test first resolved IP
			ip := ips[0].String()
			addr := net.JoinHostPort(ip, tc.port)
			t.Logf("Testing IP: %s", addr)

			// Test TLS connection
			tlsOK := testTLSHandshake(t, dialer, addr)
			require.Equal(t, tc.wantTLS, tlsOK, "TLS handshake result mismatch")

			// Test HTTP connection
			httpOK := testHTTPConnection(t, dialer, addr)
			require.Equal(t, tc.wantHTTP, httpOK, "HTTP connection result mismatch")
		})
	}
}

func testTLSHandshake(t *testing.T, dialer *fasthttp.TCPDialer, addr string) bool {
	t.Helper()

	// First establish TCP connection
	conn, err := dialer.Dial(addr)
	if err != nil {
		t.Logf("TCP dial error for %s: %v", addr, err)
		return false
	}
	defer conn.Close()

	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}

	// Attempt TLS handshake
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Logf("TLS set deadline error for %s: %v", addr, err)
		return false
	}

	if err := tlsConn.Handshake(); err != nil {
		t.Logf("TLS handshake error for %s: %v", addr, err)
		return false
	}

	t.Logf("Successful TLS handshake with %s", addr)
	return true
}

func testHTTPConnection(t *testing.T, dialer *fasthttp.TCPDialer, addr string) bool {
	t.Helper()

	// Establish TCP connection
	conn, err := dialer.Dial(addr)
	if err != nil {
		t.Logf("HTTP dial error for %s: %v", addr, err)
		return false
	}
	defer conn.Close()

	// Set deadline for the entire operation
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send HTTP request
	_, err = fmt.Fprintf(conn, "HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", addr)
	if err != nil {
		t.Logf("HTTP write error for %s: %v", addr, err)
		return false
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Logf("HTTP read error for %s: %v", addr, err)
		return false
	}

	if n > 0 && string(buf[:n])[:4] == "HTTP" {
		t.Logf("Successful HTTP connection with %s", addr)
		return true
	}

	t.Logf("Invalid HTTP response from %s", addr)
	return false
}

// Optional: Add benchmark tests for connection performance
func BenchmarkTLSHandshake(b *testing.B) {
	dialer := &fasthttp.TCPDialer{
		Concurrency:      2048,
		DNSCacheDuration: 10 * time.Minute,
	}
	addr := "github.com:443"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := dialer.Dial(addr)
		if err != nil {
			b.Fatal(err)
		}

		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		})

		tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			b.Fatal(err)
		}

		tlsConn.Close()
	}
}
