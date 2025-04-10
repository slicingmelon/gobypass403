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

func TestEndPathsPayloads(t *testing.T) {
	targetURL := "http://localhost/admin/login" // Using localhost, port will be replaced
	moduleName := "end_paths"

	// 1. Generate Payloads (Does not require server address yet)
	// We need a placeholder address initially if the payload generation *needs* it,
	// but end_paths likely only uses the path part. If it needed the host/port,
	// we would need to start the server first just to get the address.
	// Assuming end_paths doesn't strictly need the real server address during generation:
	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL, // Use placeholder initially
		BypassModule: moduleName,
		// ReconCache not needed for this module
	})
	generatedPayloads := pg.GenerateEndPathsPayloads(targetURL, moduleName)
	if len(generatedPayloads) == 0 {
		t.Fatal("No payloads were generated")
	}
	numPayloads := len(generatedPayloads) // Get the exact count
	t.Logf("Generated %d payloads for %s.", numPayloads, moduleName)

	// 2. Create the correctly sized channel for server results
	receivedURIsChan := make(chan string, numPayloads)

	// 3. Start the server, passing the *correct* channel
	serverAddr, stopServer := startRawTestServer(t, receivedURIsChan)
	// Defer server stop *after* client processing is done
	defer stopServer() // This now correctly waits for server handlers

	// 4. Update payload destinations to use the actual server address
	// We need to update the generated payloads *before* sending them.
	// Alternatively, modify PayloadGenerator to take the address later,
	// or modify RequestWorkerPool to use a different target address than the one
	// potentially stored in the payload's OriginalURL/Host/Scheme.
	// For simplicity here, let's update the generated payloads:
	for i := range generatedPayloads {
		// Assuming Scheme and Host in the payload determine the *destination*
		// for the RequestWorkerPool's client.
		// We keep the OriginalURL as the placeholder if needed for other logic.
		// The RawURI remains the same.
		generatedPayloads[i].Scheme = "http" // Match the listener
		generatedPayloads[i].Host = serverAddr
	}

	// Prepare expected URIs map (can be done anytime after generation)
	expectedURIsHex := make(map[string]struct{})
	for _, p := range generatedPayloads {
		hexURI := hex.EncodeToString([]byte(p.RawURI))
		expectedURIsHex[hexURI] = struct{}{}
	}

	// 5. Send Requests using RequestWorkerPool
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Timeout = 3 * time.Second                   // Slightly longer timeout for local tests
	clientOpts.MaxRetries = 0                              // No retries for simpler testing
	clientOpts.MaxConsecutiveFailedReqs = numPayloads + 10 // Allow some failures

	// Use a reasonable number of workers for local testing
	wp := rawhttp.NewRequestWorkerPool(clientOpts, 10)
	resultsChan := wp.ProcessRequests(generatedPayloads) // Send the updated payloads

	// 6. Drain the client results channel (wait for worker pool to finish sending)
	responseCount := 0
	for range resultsChan {
		responseCount++
	}
	wp.Close() // Close the worker pool itself
	t.Logf("Client processed %d responses.", responseCount)

	// 7. Stop the Server and Wait for Handlers
	// stopServer() is deferred, but calling it explicitly signals we are done sending
	// and want the server-side processing to finish. The defer ensures cleanup.
	// The deferred stopServer() call WILL wait for the WaitGroup.

	// 8. Close the Server's Results Channel (NOW it's safe)
	close(receivedURIsChan)

	// 9. Verify Received URIs
	receivedURIsHex := make(map[string]struct{})
	for uri := range receivedURIsChan { // Drain the channel completely
		hexURI := hex.EncodeToString([]byte(uri))
		receivedURIsHex[hexURI] = struct{}{}
	}

	// Comparison (exact match required)
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
			// Use t.Fatalf if *any* missing URI is critical and should stop the test
			t.Fatalf("URIs expected but not received by server:\n%s", strings.Join(missing, "\n"))
		}
		if len(extra) > 0 {
			// This usually indicates a problem in the test server logic or unexpected client behavior
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
			t.Logf("Successfully verified %d unique received URIs against expected URIs.", len(receivedURIsHex))
		}
	}
}
