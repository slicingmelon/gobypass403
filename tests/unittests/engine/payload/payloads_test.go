package tests

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
)

func TestPayloadSeedRoundTrip(t *testing.T) {
	// Test case matching your HeaderIP job
	original := payload.BypassPayload{
		Scheme: "https",
		Host:   "www.example.com",
		RawURI: "/admin",
		Headers: []payload.Headers{{
			Header: "X-AppEngine-Trusted-IP-Request",
			Value:  "1",
		}},
	}

	// Generate seed
	seed := "ywHwygH_BCkBgFkEAQgGAQYBBWh0dHBzAjJzdGFnZTktcHJvYmlsbGVyLW1pbGVoaWdobWVkaWEucHJvamVjdDFzZXJ2aWNlLmNvbQNeLzBkMy9kYzQvNTk4L2IyZS80NGIvNGE1LzMzNS9iZWIvZjM3L2VhNS85NS92aWRlby9mZTBjZDhiZTA0M2I1NWQ1ZTRlYjA1YjIzMmU0Mzc4NGFiZGYyOTMyLm1wNAQDR0VUBQEQWC1UcnVlLUNsaWVudC1JUApub3JlYWxob3N0"
	t.Logf("Generated seed: %s", seed)
	// Recover data
	recovered, err := payload.DecodePayloadToken(seed)

	if err != nil {
		t.Fatalf("Failed to recover seed: %v", err)
	}
	// Compare
	t.Logf("Original URL: %s, Recovered URL: %s", original.Scheme+"://"+original.Host+original.RawURI, recovered.Scheme+"://"+recovered.Host+recovered.RawURI)
	t.Logf("Original Headers: %+v", original.Headers)
	t.Logf("Recovered Headers: %+v", recovered.Headers)
	if original.Scheme+"://"+original.Host+original.RawURI != recovered.Scheme+"://"+recovered.Host+recovered.RawURI {
		t.Errorf("URLs don't match")
	}
	if len(original.Headers) != len(recovered.Headers) {
		t.Errorf("Header count mismatch: %d != %d", len(original.Headers), len(recovered.Headers))
	}
	for i, h := range original.Headers {
		if recovered.Headers[i].Header != h.Header || recovered.Headers[i].Value != h.Value {
			t.Errorf("Header %d mismatch: %+v != %+v", i, h, recovered.Headers[i])
		}
	}
}

// Helper function to start a raw TCP test server
func startRawTestServer(t *testing.T, receivedURIsChan chan<- string) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0") // Listen on random free port
	if err != nil {
		t.Fatalf("Failed to start test server listener: %v", err)
	}

	serverAddr := listener.Addr().String()
	t.Logf("Test server listening on: %s", serverAddr)

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	// Accept connections loop
	go func() {
		<-ctx.Done() // Wait for cancellation signal
		listener.Close()
		t.Log("Test server listener closed.")
	}()

	go func() {
		defer wg.Done() // Decrement wait group when accept loop finishes
		wg.Add(1)
		for {
			conn, err := listener.Accept()
			if err != nil {
				// Check if the error is due to the listener being closed.
				if ctx.Err() != nil {
					t.Log("Test server accept loop stopped.")
					return // Expected error when listener is closed
				}
				t.Errorf("Test server accept error: %v", err)
				return // Unexpected error
			}

			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				handleRawTestConnection(t, c, receivedURIsChan)
			}(conn)
		}
	}()

	// Teardown function
	stopServer := func() {
		cancel()  // Signal goroutines to stop
		wg.Wait() // Wait for all connection handlers and accept loop to finish
		t.Log("Test server stopped.")
	}

	return serverAddr, stopServer
}

// Handles a single raw connection for the test server
func handleRawTestConnection(t *testing.T, conn net.Conn, receivedURIsChan chan<- string) {
	t.Helper()
	reader := bufio.NewReader(conn)
	requestLine, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		// Ignore timeout errors which might happen if client closes early
		if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "forcibly closed") {
			t.Logf("Test server read error: %v", err)
		}
		return // Can't read request line
	}

	requestLine = strings.TrimSpace(requestLine)
	parts := strings.Split(requestLine, " ")
	if len(parts) >= 2 {
		receivedURI := parts[1]
		// Send the raw URI received back for comparison
		select {
		case receivedURIsChan <- receivedURI:
		case <-time.After(1 * time.Second): // Timeout to prevent blocking test
			t.Logf("Timeout sending received URI '%s' to channel", receivedURI)
		}
	} else {
		t.Logf("Received malformed request line: %s", requestLine)
	}

	// Send a minimal valid HTTP response so the client doesn't error out
	response := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	_, err = conn.Write([]byte(response))
	if err != nil {
		if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "forcibly closed") {
			t.Logf("Test server write error: %v", err)
		}
	}
}
