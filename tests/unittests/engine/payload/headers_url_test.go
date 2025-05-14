package tests

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
	"github.com/slicingmelon/gobypass403/core/engine/rawhttp"
)

func TestHeadersURLPayloads(t *testing.T) {
	startTime := time.Now()
	t.Logf("TestHeadersURLPayloads started at: %s", startTime.Format(time.RFC3339Nano))

	baseTargetURL := "http://localhost/admin/login" // Base URL, port will be replaced
	moduleName := "headers_url"

	// 1. Start a listener to get a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	serverAddr := listener.Addr().String() // host:port

	// Update the target URL with the actual server address
	targetURL := strings.Replace(baseTargetURL, "localhost", serverAddr, 1)
	t.Logf("Updated target URL to: %s (took %s)", targetURL, time.Since(startTime))

	// 2. Generate Payloads with the ACTUAL server address
	pgStartTime := time.Now()
	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL, // Now using actual server address
		BypassModule: moduleName,
	})
	generatedPayloads := pg.GenerateHeadersURLPayloads(targetURL, moduleName)
	if len(generatedPayloads) == 0 {
		t.Log("No payloads were generated, test might not proceed as expected.")
	}
	numPayloads := len(generatedPayloads)
	t.Logf("Generated %d payloads for %s. (took %s)", numPayloads, moduleName, time.Since(pgStartTime))

	// Dynamically size the channel based on the number of payloads
	receivedDataChan := make(chan RequestData, numPayloads)

	// Start the test server using the listener and correctly sized channel
	serverStartTime := time.Now()
	stopServer := startRawTestServerWithListener(t, listener, receivedDataChan)
	defer stopServer()
	t.Logf("Test server started. (took %s)", time.Since(serverStartTime))

	// Goroutine to collect received requests concurrently
	var collectedRequests []RequestData
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for reqData := range receivedDataChan {
			collectedRequests = append(collectedRequests, reqData)
		}
	}()

	// Create maps to track expected URIs and headers
	expectedURIs := make(map[string]bool)
	expectedHeaders := make(map[string]map[string]bool) // map[headerName][headerValue]bool

	// Update payload destinations and track expected components
	for i := range generatedPayloads {
		// Ensure each payload has the correct server address
		generatedPayloads[i].Scheme = "http"
		generatedPayloads[i].Host = serverAddr

		// Track expected URI for each request
		expectedURIs[generatedPayloads[i].RawURI] = true

		// Track expected headers for each request
		for _, h := range generatedPayloads[i].Headers {
			if expectedHeaders[h.Header] == nil {
				expectedHeaders[h.Header] = make(map[string]bool)
			}
			expectedHeaders[h.Header][h.Value] = true
		}
	}
	t.Logf("Prepared %d unique URIs and %d unique header types for verification",
		len(expectedURIs), len(expectedHeaders))

	// Send Requests using RequestWorkerPool
	clientSendStartTime := time.Now()
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Timeout = 2 * time.Second
	clientOpts.MaxRetries = 0
	clientOpts.MaxConsecutiveFailedReqs = 100

	// Use a reasonable number of workers for local testing
	wp := rawhttp.NewRequestWorkerPool(clientOpts, 20)
	defer wp.Close()

	resultsChan := wp.ProcessRequests(generatedPayloads)

	// Drain the results channel
	responseCount := 0
	for range resultsChan {
		responseCount++
	}
	t.Logf("Client processed %d responses out of %d payloads. (took %s to send and drain)",
		responseCount, numPayloads, time.Since(clientSendStartTime))

	// Explicitly stop the server and wait for all its goroutines to finish
	serverStopStartTime := time.Now()
	t.Log("Stopping test server...")
	stopServer()
	t.Logf("Test server stopped. (took %s)", time.Since(serverStopStartTime))

	// Now it's safe to close receivedDataChan, as all server handlers are done
	close(receivedDataChan)

	// Wait for the collector goroutine to finish processing all items from the channel
	collectorWaitStartTime := time.Now()
	t.Log("Waiting for request collector to finish...")
	collectWg.Wait()
	t.Logf("Request collector finished. (took %s)", time.Since(collectorWaitStartTime))

	// Verify received requests with component-wise verification
	verificationStartTime := time.Now()
	receivedCount := len(collectedRequests)
	t.Logf("Server received %d total requests for verification", receivedCount)

	// Track counters
	verifiedURIs := make(map[string]bool)
	verifiedHeaders := make(map[string]map[string]bool)

	// Initialize verified headers map with same structure as expected
	for header, values := range expectedHeaders {
		verifiedHeaders[header] = make(map[string]bool)
		for value := range values {
			verifiedHeaders[header][value] = false // Initialize all to false
		}
	}

	// Process each received request
	for _, reqData := range collectedRequests {
		// Track URI
		verifiedURIs[reqData.URI] = true

		// Parse and track headers
		lines := strings.Split(reqData.FullRequest, "\r\n")
		for _, line := range lines {
			if strings.Contains(line, ": ") {
				parts := strings.SplitN(line, ": ", 2)
				if len(parts) == 2 {
					headerName := parts[0]
					headerValue := parts[1]

					// Check if it's one of our expected headers
					if valueMap, exists := verifiedHeaders[headerName]; exists {
						if _, valueExists := valueMap[headerValue]; valueExists {
							verifiedHeaders[headerName][headerValue] = true
						}
					}
				}
			}
		}
	}

	// Verify URIs
	missingURIs := make([]string, 0)
	for uri := range expectedURIs {
		if !verifiedURIs[uri] {
			missingURIs = append(missingURIs, uri)
		}
	}

	if len(missingURIs) > 0 {
		if len(missingURIs) > 5 {
			t.Errorf("%d expected URIs not found in requests. First 5:", len(missingURIs))
			for i := 0; i < 5 && i < len(missingURIs); i++ {
				t.Errorf("  - Missing URI: %s", missingURIs[i])
			}
		} else {
			t.Errorf("Expected URIs not found in requests: %s", strings.Join(missingURIs, ", "))
		}
	} else {
		t.Logf("Successfully verified all %d expected URIs were sent", len(expectedURIs))
	}

	// Verify Headers
	missingHeaderValues := 0

	for header, valueMap := range verifiedHeaders {
		for value, found := range valueMap {
			if !found {
				missingHeaderValues++
				if missingHeaderValues <= 5 {
					t.Errorf("Missing header value: %s: %s", header, value)
				}
			}
		}
	}

	if missingHeaderValues > 0 {
		t.Errorf("Total of %d expected header values not found in requests", missingHeaderValues)
	} else {
		t.Logf("Successfully verified all expected header values were sent")
	}

	// Count verified header types
	verifiedHeaderTypes := 0
	for _, valueMap := range verifiedHeaders {
		for _, found := range valueMap {
			if found {
				verifiedHeaderTypes++
				break
			}
		}
	}
	t.Logf("Verified %d/%d header types were used in requests", verifiedHeaderTypes, len(expectedHeaders))

	t.Logf("Verification finished. (took %s)", time.Since(verificationStartTime))
	t.Logf("TestHeadersURLPayloads finished. Total time: %s", time.Since(startTime))
}
