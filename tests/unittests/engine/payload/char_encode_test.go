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

func TestCharEncodePayloads(t *testing.T) {
	targetURL := "http://localhost/admin/login" // Using localhost, port will be replaced
	moduleName := "char_encode"

	// 1. Generate Payloads
	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: moduleName,
		// ReconCache not needed for this module
	})
	// Note: GenerateCharEncodePayloads internally generates payloads for
	// "char_encode", "char_encode_double", and "char_encode_triple"
	// and assigns the BypassModule field accordingly within the function.
	// We collect *all* generated payloads here.
	generatedPayloads := pg.GenerateCharEncodePayloads(targetURL, moduleName) // Calls the correct function
	if len(generatedPayloads) == 0 {
		t.Fatal("No payloads were generated")
	}

	numPayloads := len(generatedPayloads)
	t.Logf("Generated %d payloads for char_encode variants.", numPayloads)

	// Channel to collect requests received by the server - use exact size
	receivedDataChan := make(chan RequestData, numPayloads)

	// Start the raw test server
	serverAddr, stopServer := startRawTestServer(t, receivedDataChan)
	defer stopServer()

	// Replace localhost with the actual server address for the target URL
	targetURL = strings.Replace(targetURL, "localhost", serverAddr, 1)

	expectedURIsHex := make(map[string]struct{})
	for _, p := range generatedPayloads {
		hexURI := hex.EncodeToString([]byte(p.RawURI))
		expectedURIsHex[hexURI] = struct{}{}
		// t.Logf("Expected RawURI: %s (Hex: %s)", p.RawURI, hexURI) // Debug logging
	}

	// 2. Send Requests using RequestWorkerPool
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Timeout = 2 * time.Second      // Shorter timeout for tests
	clientOpts.MaxRetries = 0                 // No retries for simpler testing
	clientOpts.MaxConsecutiveFailedReqs = 100 // Allow failures during testing

	// Use a reasonable number of workers for local testing
	wp := rawhttp.NewRequestWorkerPool(clientOpts, 10)
	defer wp.Close()

	resultsChan := wp.ProcessRequests(generatedPayloads)

	// Drain the results channel (we don't strictly need the results, just need to wait)
	// But keep track of how many responses we got back
	responseCount := 0
	for range resultsChan {
		responseCount++
	}
	// Brief pause to allow server goroutines to potentially send to channel
	time.Sleep(100 * time.Millisecond)
	close(receivedDataChan) // Close channel once pool is done and results drained

	t.Logf("Client processed %d responses.", responseCount)

	// 3. Verify Received URIs
	receivedURIsHex := make(map[string]struct{})
	for reqData := range receivedDataChan { // Drain the channel completely
		hexURI := hex.EncodeToString([]byte(reqData.URI))
		receivedURIsHex[hexURI] = struct{}{}
		// t.Logf("Received RawURI: %s (Hex: %s)", reqData.URI, hexURI) // Debug logging
	}

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
