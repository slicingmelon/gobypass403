package tests

import (
	"encoding/hex"
	"fmt"
	"net" // Required for net.Listener
	"strings"
	"sync" // Required for sync.WaitGroup
	"testing"
	"time"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
	"github.com/slicingmelon/gobypass403/core/engine/rawhttp"
)

func TestEndPathsPayloads(t *testing.T) {
	startTime := time.Now()
	t.Logf("TestEndPathsPayloads started at: %s", startTime.Format(time.RFC3339Nano))

	baseTargetURL := "http://localhost/admin/login" // Base URL, port will be replaced
	moduleName := "end_paths"

	// 1. Start a listener to get a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	serverAddr := listener.Addr().String() // host:port
	// The listener will be closed by stopServer via startRawTestServerWithListener

	// Update the target URL with the actual server address
	targetURL := strings.Replace(baseTargetURL, "localhost", serverAddr, 1)
	t.Logf("Updated target URL to: %s (took %s)", targetURL, time.Since(startTime))

	// 2. Generate Payloads with the ACTUAL server address
	pgStartTime := time.Now()
	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL, // Use the actual targetURL with the correct port
		BypassModule: moduleName,
	})
	generatedPayloads := pg.GenerateEndPathsPayloads(targetURL, moduleName)
	if len(generatedPayloads) == 0 {
		// For this test, we expect payloads. If it can be 0, adjust the check.
		t.Fatal("No payloads were generated for end_paths")
	}
	numPayloads := len(generatedPayloads)
	t.Logf("Generated %d payloads for %s. (took %s)", numPayloads, moduleName, time.Since(pgStartTime))

	// 3. Dynamically size the channel based on the number of payloads
	receivedDataChan := make(chan RequestData, numPayloads)

	// 4. Start the test server using the listener and correctly sized channel
	serverStartTime := time.Now()
	stopServer := startRawTestServerWithListener(t, listener, receivedDataChan)
	defer stopServer() // Ensure server is stopped eventually
	t.Logf("Test server started. (took %s)", time.Since(serverStartTime))

	// 5. Goroutine to collect received requests concurrently
	var collectedRequests []RequestData
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for reqData := range receivedDataChan {
			collectedRequests = append(collectedRequests, reqData)
		}
	}()

	// 6. Update payload destinations to use the actual server address and scheme.
	// GenerateEndPathsPayloads should ideally set these based on the targetURL.
	// If not, this step is crucial. Assuming BypassPayload needs Scheme and Host for client.
	for i := range generatedPayloads {
		generatedPayloads[i].Scheme = "http"   // Test server is HTTP
		generatedPayloads[i].Host = serverAddr // Actual host:port
	}
	t.Logf("Updated payload destinations to %s", serverAddr)

	// 7. Prepare expected URIs map (can be done anytime after generation)
	expectedURIsHex := make(map[string]struct{})
	for _, p := range generatedPayloads {
		hexURI := hex.EncodeToString([]byte(p.RawURI)) // RawURI is what we test for path modifications
		expectedURIsHex[hexURI] = struct{}{}
	}

	// 8. Send Requests using RequestWorkerPool
	clientSendStartTime := time.Now()
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Timeout = 3 * time.Second // Timeout for each request
	clientOpts.MaxRetries = 0
	clientOpts.MaxConsecutiveFailedReqs = numPayloads + 10

	wp := rawhttp.NewRequestWorkerPool(clientOpts, 10) // Number of client workers
	defer wp.Close()                                   // Ensure worker pool is closed

	resultsChan := wp.ProcessRequests(generatedPayloads)

	// 9. Drain the client results channel
	responseCount := 0
	for range resultsChan {
		responseCount++
	}
	t.Logf("Client processed %d responses out of %d payloads. (took %s to send and drain)", responseCount, numPayloads, time.Since(clientSendStartTime))

	// 10. Explicitly stop the server and wait for its goroutines
	serverStopStartTime := time.Now()
	t.Log("Stopping test server...")
	stopServer() // Call explicitly to wait for server handlers
	t.Logf("Test server stopped. (took %s)", time.Since(serverStopStartTime))

	// 11. Close receivedDataChan (safe now)
	close(receivedDataChan)

	// 12. Wait for the collector goroutine
	collectorWaitStartTime := time.Now()
	t.Log("Waiting for request collector to finish...")
	collectWg.Wait()
	t.Logf("Request collector finished. (took %s)", time.Since(collectorWaitStartTime))

	// 13. Verify Received URIs
	verificationStartTime := time.Now()
	receivedURIsHex := make(map[string]struct{})
	for _, reqData := range collectedRequests {
		hexURI := hex.EncodeToString([]byte(reqData.URI)) // URI from RequestData is what the server saw
		receivedURIsHex[hexURI] = struct{}{}
	}
	t.Logf("Server received %d total requests, %d unique URIs", len(collectedRequests), len(receivedURIsHex))

	// Comparison
	if len(expectedURIsHex) != len(receivedURIsHex) {
		t.Errorf("Mismatch in count: Expected %d unique URIs, Server received %d unique URIs", len(expectedURIsHex), len(receivedURIsHex))
		// (Error logging for missing/extra URIs as before)
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
	t.Logf("Verification finished. (took %s)", time.Since(verificationStartTime))
	t.Logf("TestEndPathsPayloads finished. Total time: %s", time.Since(startTime))
}
