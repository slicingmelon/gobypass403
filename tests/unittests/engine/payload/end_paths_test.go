package tests

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
	"github.com/slicingmelon/gobypass403/core/engine/rawhttp"
)

// NOTE: The helper functions startRawTestServer and handleRawTestConnection
// are assumed to be present (either in this file or a shared helper file).

func TestEndPathsPayloads(t *testing.T) {
	targetURL := "http://localhost/admin/login" // Using localhost, port will be replaced
	moduleName := "end_paths"

	// Start the raw test server FIRST, before generating payloads that depend on its address.
	// Create a temporary channel just for starting the server.
	tempChan := make(chan string, 1) // Temporary channel
	serverAddr, stopServer := startRawTestServer(t, tempChan)
	defer stopServer()
	close(tempChan) // Close the temp channel, we don't need it anymore

	// Replace localhost with the actual server address for the target URL
	targetURL = strings.Replace(targetURL, "localhost", serverAddr, 1)

	// 1. Generate Payloads
	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: moduleName,
		// ReconCache not needed for this module
	})
	generatedPayloads := pg.GenerateEndPathsPayloads(targetURL, moduleName)
	if len(generatedPayloads) == 0 {
		t.Fatal("No payloads were generated")
	}
	numPayloads := len(generatedPayloads) // Get the exact count
	t.Logf("Generated %d payloads for %s.", numPayloads, moduleName)

	// Channel to collect URIs received by the server - SIZE DYNAMICALLY
	receivedURIsChan := make(chan string, numPayloads) // <-- Use the exact count

	// Prepare expected URIs map
	expectedURIsHex := make(map[string]struct{})
	for _, p := range generatedPayloads {
		hexURI := hex.EncodeToString([]byte(p.RawURI))
		expectedURIsHex[hexURI] = struct{}{}
		// t.Logf("Expected RawURI: %s (Hex: %s)", p.RawURI, hexURI) // Debug logging
	}

	// 2. Send Requests using RequestWorkerPool
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Timeout = 2 * time.Second                  // Shorter timeout for tests
	clientOpts.MaxRetries = 0                             // No retries for simpler testing
	clientOpts.MaxConsecutiveFailedReqs = numPayloads + 1 // Allow all potential requests to fail if needed

	// Use a reasonable number of workers for local testing
	wp := rawhttp.NewRequestWorkerPool(clientOpts, 10)
	defer wp.Close()

	// **Important**: We need the server running with the *correct* channel before processing requests
	// Since the server helpers were already started with tempChan, we restart them here
	// OR (better) modify the helper to accept the channel after creation.
	// For simplicity here, let's imagine the helpers are defined in this file and we pass the correct channel now.
	// If helpers are separate, you'll need to refactor them slightly.
	// --- Assuming helpers are modified or defined locally for clarity ---
	// (If helpers are separate, you'd pass receivedURIsChan to them now instead of tempChan)

	resultsChan := wp.ProcessRequests(generatedPayloads)

	// Drain the results channel
	responseCount := 0
	for range resultsChan {
		responseCount++
	}
	// Brief pause remains useful
	time.Sleep(100 * time.Millisecond)
	close(receivedURIsChan) // Close channel

	t.Logf("Client processed %d responses.", responseCount)

	// 3. Verify Received URIs
	receivedURIsHex := make(map[string]struct{})
	for uri := range receivedURIsChan { // Drain the channel completely
		hexURI := hex.EncodeToString([]byte(uri))
		receivedURIsHex[hexURI] = struct{}{}
		// t.Logf("Received RawURI: %s (Hex: %s)", uri, hexURI) // Debug logging
	}

	// Comparison (exact match required)
	if len(expectedURIsHex) != len(receivedURIsHex) {
		t.Errorf("Mismatch in count: Expected %d unique URIs, Server received %d unique URIs", len(expectedURIsHex), len(receivedURIsHex))

		// Find missing/extra (same logic as before)
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
		// If counts match, verify all expected URIs were received (same logic as before)
		for hexExp := range expectedURIsHex {
			if _, found := receivedURIsHex[hexExp]; !found {
				rawBytes, _ := hex.DecodeString(hexExp)
				t.Errorf("Expected URI not received by server: '%s' (Hex: %s)", string(rawBytes), hexExp)
			}
		}
		t.Logf("Successfully verified %d unique received URIs against expected URIs.", len(receivedURIsHex))
	}
}

// --- Place or import startRawTestServer and handleRawTestConnection here ---
// (Code for these helpers omitted for brevity, assume they are available)
