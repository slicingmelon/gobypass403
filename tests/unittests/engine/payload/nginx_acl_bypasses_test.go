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

func TestNginxACLsBypassPayloads(t *testing.T) {
	// Use a URL with multiple path segments
	targetURL := "http://localhost/admin/config/users"
	moduleName := "nginx_acl_bypasses"

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
	generatedPayloads := pg.GenerateNginxACLsBypassPayloads(targetURL, moduleName)
	if len(generatedPayloads) == 0 {
		t.Fatalf("No payloads were generated for %s", moduleName)
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

	// Prepare expected URIs map
	expectedURIsHex := make(map[string]struct{})
	for _, p := range generatedPayloads {
		hexURI := hex.EncodeToString([]byte(p.RawURI))
		expectedURIsHex[hexURI] = struct{}{}
	}
	// Log if the number of unique expected URIs is different from generated count
	if len(expectedURIsHex) != numPayloads {
		t.Logf("Warning: Number of unique expected URIs (%d) differs from total generated payloads (%d) for %s. This indicates duplicate RawURIs were generated.", len(expectedURIsHex), numPayloads, moduleName)
	}

	// 4. Send Requests
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Timeout = 5 * time.Second                   // Allow slightly longer timeout
	clientOpts.MaxRetries = 0                              // No retries
	clientOpts.MaxConsecutiveFailedReqs = numPayloads + 10 // Allow failures

	wp := rawhttp.NewRequestWorkerPool(clientOpts, 20) // Use a reasonable number of workers
	resultsChan := wp.ProcessRequests(generatedPayloads)

	// 5. Drain client results
	responseCount := 0
	for range resultsChan {
		responseCount++
	}
	wp.Close()
	t.Logf("Client processed %d responses out of %d payloads for %s.", responseCount, numPayloads, moduleName)

	// 6. Allow a moment for server handlers and then close the channel
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
		t.Errorf("Mismatch in count for %s: Expected %d unique URIs, Server received %d unique URIs", moduleName, expectedCount, receivedCount)

		// Find and log ALL missing/extra URIs
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
		// Use Fatalf only if missing URIs are found, as this indicates a core problem.
		if len(missing) > 0 {
			t.Fatalf("URIs expected but not received by server for %s:\n%s", moduleName, strings.Join(missing, "\n"))
		}
		if len(extra) > 0 {
			t.Errorf("URIs received by server but not expected for %s:\n%s", moduleName, strings.Join(extra, "\n"))
		}
	} else {
		// Counts match, now perform FULL verification of each URI
		match := true
		for hexExp := range expectedURIsHex {
			if _, found := receivedURIsHex[hexExp]; !found {
				rawBytes, _ := hex.DecodeString(hexExp)
				t.Errorf("Expected URI not received by server for %s: '%s' (Hex: %s)", moduleName, string(rawBytes), hexExp)
				match = false
			}
		}
		if match {
			t.Logf("Successfully verified all %d unique received URIs match the %d expected unique URIs for %s.", receivedCount, expectedCount, moduleName)
		}
	}
}
