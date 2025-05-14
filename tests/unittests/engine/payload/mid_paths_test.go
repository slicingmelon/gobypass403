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

func TestMidPathsPayloads(t *testing.T) {
	// Use a URL with multiple path segments for better testing
	targetURL := "http://localhost/admin/config/users"
	moduleName := "mid_paths"

	// 1. Start the test server FIRST to get the actual server address
	receivedDataChan := make(chan RequestData, 100) // Use a reasonable buffer initially
	serverAddr, stopServer := startRawTestServer(t, receivedDataChan)
	defer stopServer() // Ensure server stops eventually

	// Update the target URL with the actual server address
	targetURL = strings.Replace(targetURL, "localhost", serverAddr, 1)
	t.Logf("Updated target URL to: %s", targetURL)

	// 2. Generate Payloads with the ACTUAL server address
	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL, // Now using actual server address
		BypassModule: moduleName,
	})
	generatedPayloads := pg.GenerateMidPathsPayloads(targetURL, moduleName)
	if len(generatedPayloads) == 0 {
		t.Fatal("No payloads were generated")
	}
	numPayloads := len(generatedPayloads)
	t.Logf("Generated %d payloads for %s.", numPayloads, moduleName)

	// 3. Double check that each payload has the correct server address
	for i := range generatedPayloads {
		if generatedPayloads[i].Host != serverAddr {
			t.Logf("Warning: Fixing payload host from %s to %s", generatedPayloads[i].Host, serverAddr)
			generatedPayloads[i].Host = serverAddr
		}
	}

	// Prepare expected URIs map (can be done anytime after generation)
	expectedURIsHex := make(map[string]struct{})
	for _, p := range generatedPayloads {
		hexURI := hex.EncodeToString([]byte(p.RawURI))
		expectedURIsHex[hexURI] = struct{}{}
	}
	if len(expectedURIsHex) != numPayloads {
		t.Logf("Warning: Number of unique expected URIs (%d) differs from total generated payloads (%d). This might indicate duplicate RawURIs generated.", len(expectedURIsHex), numPayloads)
	}

	// 4. Send Requests using RequestWorkerPool
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Timeout = 3 * time.Second      // Timeout for local tests
	clientOpts.MaxRetries = 0                 // No retries
	clientOpts.MaxConsecutiveFailedReqs = 100 // Allow some failures

	wp := rawhttp.NewRequestWorkerPool(clientOpts, 10) // 10 workers
	resultsChan := wp.ProcessRequests(generatedPayloads)

	// 5. Drain the client results channel
	responseCount := 0
	for range resultsChan {
		responseCount++
	}
	wp.Close() // Close the worker pool
	t.Logf("Client processed %d responses out of %d payloads.", responseCount, numPayloads)

	// 6. Allow a moment for server handlers to finish and then close the channel
	time.Sleep(500 * time.Millisecond) // Increased pause time
	close(receivedDataChan)

	// 7. Verify Received URIs
	receivedURIsHex := make(map[string]struct{})
	receivedCount := 0
	for reqData := range receivedDataChan {
		receivedCount++
		hexURI := hex.EncodeToString([]byte(reqData.URI))
		receivedURIsHex[hexURI] = struct{}{}
	}

	t.Logf("Server received %d total requests, %d unique URIs", receivedCount, len(receivedURIsHex))

	// 8. Comparison
	expectedCount := len(expectedURIsHex)
	receivedCount = len(receivedURIsHex)

	if expectedCount != receivedCount {
		t.Errorf("Mismatch in count: Expected %d unique URIs, Server received %d unique URIs", expectedCount, receivedCount)

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
			t.Fatalf("URIs expected but not received by server:\n%s", strings.Join(missing, "\n"))
		}
		if len(extra) > 0 {
			t.Errorf("URIs received by server but not expected:\n%s", strings.Join(extra, "\n"))
		}
	} else {
		// If counts match, verify all expected URIs were received
		match := true
		for hexExp := range expectedURIsHex {
			if _, found := receivedURIsHex[hexExp]; !found {
				rawBytes, _ := hex.DecodeString(hexExp)
				t.Errorf("Expected URI not received by server: '%s' (Hex: %s)", string(rawBytes), hexExp)
				match = false
			}
		}
		if match {
			t.Logf("Successfully verified %d unique received URIs against %d expected unique URIs.", receivedCount, expectedCount)
		}
	}
}
