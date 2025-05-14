package tests

import (
	"bufio"
	"context"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
)

// RequestData holds both the URI and full raw HTTP request received by the test server
type RequestData struct {
	URI         string // The URI portion of the request
	FullRequest string // The complete raw HTTP request (including request line, headers, body)
	HexEncoded  string // Hex-encoded raw request for precise comparison
}

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

// Helper function to start a raw TCP test server using an existing listener
func startRawTestServerWithListener(t *testing.T, listener net.Listener, receivedDataChan chan<- RequestData) func() {
	t.Helper()
	serverAddr := listener.Addr().String() // Get address for logging, though caller knows it
	t.Logf("Test server (with listener) starting on: %s", serverAddr)

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	// Goroutine to close the listener when context is cancelled
	go func() {
		<-ctx.Done() // Wait for cancellation signal
		listener.Close()
		t.Logf("Test server listener on %s closed.", serverAddr)
	}()

	wg.Add(1) // Add to WaitGroup for the accept loop goroutine
	go func() {
		defer wg.Done() // Decrement wait group when accept loop finishes
		for {
			conn, err := listener.Accept()
			if err != nil {
				// Check if the error is due to the listener being closed.
				if ctx.Err() != nil || strings.Contains(err.Error(), "use of closed network connection") {
					t.Logf("Test server accept loop on %s stopped.", serverAddr)
					return // Expected error when listener is closed
				}
				t.Errorf("Test server accept error on %s: %v", serverAddr, err)
				return // Unexpected error
			}

			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				handleRawTestConnection(t, c, receivedDataChan)
			}(conn)
		}
	}()

	// Teardown function
	stopServer := func() {
		cancel()  // Signal goroutines to stop
		wg.Wait() // Wait for all connection handlers and accept loop to finish
		t.Logf("Test server on %s stopped gracefully.", serverAddr)
	}

	return stopServer
}

// Helper function to start a raw TCP test server
func startRawTestServer(t *testing.T, receivedDataChan chan<- RequestData) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0") // Listen on random free port
	if err != nil {
		t.Fatalf("Failed to start test server listener: %v", err)
	}
	serverAddr := listener.Addr().String()
	// Note: Original t.Logf("Test server listening on: %s", serverAddr) is now in startRawTestServerWithListener

	// Pass the created listener to the new function
	stopServerFunc := startRawTestServerWithListener(t, listener, receivedDataChan)

	return serverAddr, stopServerFunc
}

// Handles a single raw connection for the test server
func handleRawTestConnection(t *testing.T, conn net.Conn, receivedDataChan chan<- RequestData) {
	t.Helper()

	// Set a read deadline to avoid hanging
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Instead of just reading the first line, read the entire request
	var requestBuffer strings.Builder
	reader := bufio.NewReader(conn)

	// Read request line first (still needed to extract URI for backward compatibility)
	requestLine, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "forcibly closed") {
			t.Logf("Test server read error: %v", err)
		}
		return
	}
	requestBuffer.WriteString(requestLine)

	// Extract URI for backward compatibility
	requestLineParts := strings.Split(strings.TrimSpace(requestLine), " ")
	var receivedURI string
	if len(requestLineParts) >= 2 {
		receivedURI = requestLineParts[1]
	} else {
		t.Logf("Received malformed request line: %s", requestLine)
		return
	}

	// Read headers until empty line
	emptyLineFound := false
	for !emptyLineFound {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "forcibly closed") {
				t.Logf("Test server read error when reading headers: %v", err)
			}
			break
		}
		requestBuffer.WriteString(line)

		// Empty line (just "\r\n") indicates end of headers
		if line == "\r\n" || line == "\n" {
			emptyLineFound = true
		}

		// Break on EOF
		if err == io.EOF {
			break
		}
	}

	// Try to read body if Content-Length header was present
	// For simplicity in this test server we'll read a limited amount
	bodyBuf := make([]byte, 8192) // Read up to 8KB of body
	n, _ := reader.Read(bodyBuf)
	if n > 0 {
		requestBuffer.Write(bodyBuf[:n])
	}

	// Get the full raw request
	fullRequest := requestBuffer.String()

	// Convert to hex for precise comparison including invisible characters
	hexRequest := hex.EncodeToString([]byte(fullRequest))

	// Create RequestData struct
	requestData := RequestData{
		URI:         receivedURI,
		FullRequest: fullRequest,
		HexEncoded:  hexRequest,
	}

	// Send the request data
	select {
	case receivedDataChan <- requestData:
	case <-time.After(1 * time.Second):
		t.Logf("Timeout sending received request data for URI '%s'", receivedURI)
	}

	// Send a minimal valid HTTP response so the client doesn't error out
	response := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	_, err = conn.Write([]byte(response))
	if err != nil {
		if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "forcibly closed") {
			t.Logf("Test server write error: %v", err)
		}
	}

	// Debug logging for request details - COMMENTED OUT FOR PERFORMANCE
	t.Logf("Received request with URI: %s", receivedURI)
	t.Logf("Full raw request length: %d bytes", len(fullRequest))
}
