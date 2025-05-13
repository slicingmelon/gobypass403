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

	// 1. Generate Payloads (Does not require server address yet)
	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL, // Use placeholder initially
		BypassModule: moduleName,
	})
	generatedPayloads := pg.GenerateMidPathsPayloads(targetURL, moduleName)
	if len(generatedPayloads) == 0 {
		t.Fatal("No payloads were generated")
	}
	numPayloads := len(generatedPayloads)
	t.Logf("Generated %d payloads for %s.", numPayloads, moduleName)

	// 2. Create the correctly sized channel for server results
	// Adjust buffer size if necessary, based on expected payload count
	receivedURIsChan := make(chan string, numPayloads+10) // Add some buffer

	// 3. Start the server, passing the channel
	serverAddr, stopServer := startRawTestServer(t, receivedURIsChan)
	defer stopServer() // Ensure server stops eventually

	// 4. Update payload destinations to use the actual server address
	for i := range generatedPayloads {
		generatedPayloads[i].Scheme = "http" // Match the listener
		generatedPayloads[i].Host = serverAddr
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

	// 5. Send Requests using RequestWorkerPool
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Timeout = 3 * time.Second      // Timeout for local tests
	clientOpts.MaxRetries = 0                 // No retries
	clientOpts.MaxConsecutiveFailedReqs = 100 // Allow some failures

	wp := rawhttp.NewRequestWorkerPool(clientOpts, 10) // 10 workers
	resultsChan := wp.ProcessRequests(generatedPayloads)

	// 6. Drain the client results channel
	responseCount := 0
	for range resultsChan {
		responseCount++
	}
	wp.Close() // Close the worker pool
	t.Logf("Client processed %d responses.", responseCount)

	// 7. Close the Server's Results Channel (Safe now)
	// Give a brief moment for any in-flight server handlers to send
	time.Sleep(100 * time.Millisecond)
	close(receivedURIsChan)

	// 8. Verify Received URIs
	receivedURIsHex := make(map[string]struct{})
	for uri := range receivedURIsChan { // Drain the channel
		hexURI := hex.EncodeToString([]byte(uri))
		receivedURIsHex[hexURI] = struct{}{}
	}

	// 9. Comparison
	expectedCount := len(expectedURIsHex)
	receivedCount := len(receivedURIsHex)

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
