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

func TestUnicodePathNormalizationsPayloads(t *testing.T) {
	// Use a URL with multiple path segments and characters to replace
	targetURL := "http://localhost/admin/./config/../users/"
	moduleName := "unicode_path_normalization"

	// 1. Generate Payloads
	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL, // Use placeholder initially
		BypassModule: moduleName,
	})
	generatedPayloads := pg.GenerateUnicodePathNormalizationsPayloads(targetURL, moduleName)
	if len(generatedPayloads) == 0 {
		t.Fatalf("No payloads were generated for %s", moduleName)
	}
	numPayloads := len(generatedPayloads) // This is the count *after* internal unique filtering
	t.Logf("Generated %d payloads for %s.", numPayloads, moduleName)

	// 2. Prepare expected URIs map (unique check is done inside generator)
	expectedURIsHex := make(map[string]struct{})
	for _, p := range generatedPayloads {
		hexURI := hex.EncodeToString([]byte(p.RawURI))
		if _, exists := expectedURIsHex[hexURI]; exists {
			// This should ideally not happen if the generator's unique check works
			t.Logf("Warning: Duplicate RawURI found after generation: %s (Hex: %s)", p.RawURI, hexURI)
		}
		expectedURIsHex[hexURI] = struct{}{}
	}
	// Use the count of unique expected URIs for the channel size
	expectedUniqueCount := len(expectedURIsHex)
	if expectedUniqueCount != numPayloads {
		// Log difference if the map size differs from the generator's returned slice length
		t.Logf("Note: Count of unique expected URIs (%d) differs slightly from generator's returned count (%d). Using unique count for channel.", expectedUniqueCount, numPayloads)
	}

	// 3. Create the channel for server results with the exact size needed
	receivedDataChan := make(chan RequestData, expectedUniqueCount)

	// 4. Start the server
	serverAddr, stopServer := startRawTestServer(t, receivedDataChan)
	defer stopServer() // Ensure server stops eventually

	// 5. Update payload destinations
	for i := range generatedPayloads {
		generatedPayloads[i].Scheme = "http" // Match the listener
		generatedPayloads[i].Host = serverAddr
	}

	// 6. Send Requests
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Timeout = 5 * time.Second                   // Allow slightly longer timeout
	clientOpts.MaxRetries = 0                              // No retries
	clientOpts.MaxConsecutiveFailedReqs = numPayloads + 20 // Allow some failures

	wp := rawhttp.NewRequestWorkerPool(clientOpts, 20) // Use a reasonable number of workers
	resultsChan := wp.ProcessRequests(generatedPayloads)

	// 7. Drain client results
	responseCount := 0
	for range resultsChan {
		responseCount++
	}
	wp.Close()
	t.Logf("Client processed %d responses for %s.", responseCount, moduleName)

	// 8. Close Server's Results Channel
	// Allow a moment for server handlers
	time.Sleep(200 * time.Millisecond)
	close(receivedDataChan)

	// 9. Verify Received URIs
	receivedURIsHex := make(map[string]struct{})
	for reqData := range receivedDataChan { // Drain the channel
		hexURI := hex.EncodeToString([]byte(reqData.URI))
		receivedURIsHex[hexURI] = struct{}{}
	}

	// 10. Comparison
	receivedCount := len(receivedURIsHex)

	if expectedUniqueCount != receivedCount {
		t.Errorf("Mismatch in count for %s: Expected %d unique URIs, Server received %d unique URIs", moduleName, expectedUniqueCount, receivedCount)

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
		// Use Fatalf only if missing URIs are found.
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
			t.Logf("Successfully verified all %d unique received URIs match the %d expected unique URIs for %s.", receivedCount, expectedUniqueCount, moduleName)
		}
	}
}
