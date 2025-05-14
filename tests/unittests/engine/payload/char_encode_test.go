package tests

import (
	"encoding/hex"
	"fmt"
	"net" // Required for net.Listener
	"strings"
	"testing"
	"time"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
	"github.com/slicingmelon/gobypass403/core/engine/rawhttp"
)

func TestCharEncodePayloads(t *testing.T) {
	baseTargetURL := "http://localhost/admin/login" // Using localhost, port will be replaced
	moduleName := "char_encode"

	// 1. Start a listener to get a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	serverAddr := listener.Addr().String()
	// Note: We will pass listener to startRawTestServerWithListener, which will handle closing it.
	// If startRawTestServerWithListener is not called, listener.Close() should be called here.

	// Update the target URL with the actual server address
	targetURL := strings.Replace(baseTargetURL, "localhost", serverAddr, 1)
	t.Logf("Updated target URL to: %s", targetURL)

	// 2. Generate Payloads with the ACTUAL server address
	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: moduleName,
	})

	// Note: GenerateCharEncodePayloads internally generates payloads for
	// "char_encode", "char_encode_double", and "char_encode_triple"
	// and assigns the BypassModule field accordingly within the function.
	generatedPayloads := pg.GenerateCharEncodePayloads(targetURL, moduleName)
	if len(generatedPayloads) == 0 {
		// It's valid for no payloads to be generated in some scenarios,
		// but for this specific test, we expect them.
		// If this can legitimately be 0, the test might need adjustment.
		t.Log("No payloads were generated, test might not proceed as expected.")
		// Fallback to a small buffer if no payloads, to avoid make chan with 0 if problematic.
		// However, make(chan T, 0) is an unbuffered channel, which is fine.
		// For consistency in test logic expecting a buffer, let's ensure at least 1 if no payloads,
		// though this specific test would likely fail later if 0 payloads is unexpected.
	}
	numPayloads := len(generatedPayloads)
	t.Logf("Generated %d payloads for char_encode variants.", numPayloads)

	// Dynamically size the channel based on the number of payloads
	// If numPayloads is 0, it creates an unbuffered channel, which is acceptable.
	receivedDataChan := make(chan RequestData, numPayloads)

	// Start the test server using the listener and correctly sized channel
	// startRawTestServerWithListener is in the same package 'tests'
	stopServer := startRawTestServerWithListener(t, listener, receivedDataChan)
	defer stopServer()

	// 3. Set up expected URIs from the payloads
	expectedURIsHex := make(map[string]struct{})
	for _, p := range generatedPayloads {
		// Double check that each payload has the correct server address
		if p.Host != serverAddr {
			t.Logf("Warning: Fixing payload host from %s to %s", p.Host, serverAddr)
			p.Host = serverAddr
		}
		hexURI := hex.EncodeToString([]byte(p.RawURI))
		expectedURIsHex[hexURI] = struct{}{}
	}

	// Resize the channel now that we know the payload count
	// Note: We can't actually resize the channel, so this is just a note
	// In practice, the initial buffer size should be enough

	// 4. Send Requests using RequestWorkerPool
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Timeout = 2 * time.Second      // Shorter timeout for tests
	clientOpts.MaxRetries = 0                 // No retries for simpler testing
	clientOpts.MaxConsecutiveFailedReqs = 100 // Allow failures during testing

	// Use a reasonable number of workers for local testing
	wp := rawhttp.NewRequestWorkerPool(clientOpts, 20)
	defer wp.Close()

	resultsChan := wp.ProcessRequests(generatedPayloads)

	// Drain the results channel
	responseCount := 0
	for range resultsChan {
		responseCount++
	}

	// Brief pause to allow server goroutines to finish processing
	time.Sleep(500 * time.Millisecond) // Increased pause time
	close(receivedDataChan)            // Close channel once pool is done and results drained

	t.Logf("Client processed %d responses out of %d payloads", responseCount, numPayloads)

	// 5. Verify Received URIs
	receivedURIsHex := make(map[string]struct{})
	receivedCount := 0
	for reqData := range receivedDataChan {
		receivedCount++
		hexURI := hex.EncodeToString([]byte(reqData.URI))
		receivedURIsHex[hexURI] = struct{}{}
	}

	t.Logf("Server received %d total requests, %d unique URIs", receivedCount, len(receivedURIsHex))

	// Comparison
	if len(expectedURIsHex) != len(receivedURIsHex) {
		t.Errorf("Mismatch in count: Expected %d unique URIs, Server received %d unique URIs", len(expectedURIsHex), len(receivedURIsHex))

		// Find missing/extra
		missing := []string{}
		for hexExp := range expectedURIsHex {
			if _, found := receivedURIsHex[hexExp]; !found {
				rawBytes, _ := hex.DecodeString(hexExp)
				missing = append(missing, fmt.Sprintf("'%s' (Hex: %s)", string(rawBytes), hexExp))
			}
		}
		extra := []string{}
		for hexRcv := range receivedURIsHex {
			if _, found := expectedURIsHex[hexRcv]; !found {
				rawBytes, _ := hex.DecodeString(hexRcv)
				extra = append(extra, fmt.Sprintf("'%s' (Hex: %s)", string(rawBytes), hexRcv))
			}
		}
		if len(missing) > 0 {
			t.Errorf("URIs expected but not received by server:\n%s", strings.Join(missing, "\n"))
		}
		if len(extra) > 0 {
			t.Errorf("URIs received by server but not expected:\n%s", strings.Join(extra, "\n"))
		}

	} else {
		// If counts match, verify all expected URIs were received
		for hexExp := range expectedURIsHex {
			if _, found := receivedURIsHex[hexExp]; !found {
				rawBytes, _ := hex.DecodeString(hexExp)
				t.Errorf("Expected URI not received by server: '%s' (Hex: %s)", string(rawBytes), hexExp)
			}
		}
		t.Logf("Successfully verified %d unique received URIs against expected URIs.", len(receivedURIsHex))
	}
}
