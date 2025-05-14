package tests

import (
	"strings"
	"testing"
	"time"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
	"github.com/slicingmelon/gobypass403/core/engine/rawhttp"
)

func TestHeadersURLPayloads(t *testing.T) {
	targetURL := "http://localhost/admin/login" // Using localhost, port will be replaced
	moduleName := "headers_url"

	// 1. Start the test server FIRST to get the actual server address
	receivedDataChan := make(chan RequestData, 100) // Use a reasonable buffer initially
	serverAddr, stopServer := startRawTestServer(t, receivedDataChan)
	defer stopServer()

	// Update the target URL with the actual server address
	targetURL = strings.Replace(targetURL, "localhost", serverAddr, 1)
	t.Logf("Updated target URL to: %s", targetURL)

	// 2. Generate Payloads with the ACTUAL server address
	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL, // Now using actual server address
		BypassModule: moduleName,
	})
	generatedPayloads := pg.GenerateHeadersURLPayloads(targetURL, moduleName)
	if len(generatedPayloads) == 0 {
		t.Fatal("No payloads were generated")
	}

	numPayloads := len(generatedPayloads)
	t.Logf("Generated %d payloads for headers_url module", numPayloads)

	// 3. Double check that each payload has the correct server address
	for i := range generatedPayloads {
		if generatedPayloads[i].Host != serverAddr {
			t.Logf("Warning: Fixing payload host from %s to %s", generatedPayloads[i].Host, serverAddr)
			generatedPayloads[i].Host = serverAddr
		}
	}

	// 4. Send Requests using RequestWorkerPool
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Timeout = 2 * time.Second
	clientOpts.MaxRetries = 0
	clientOpts.MaxConsecutiveFailedReqs = 100

	wp := rawhttp.NewRequestWorkerPool(clientOpts, 10)
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

	t.Logf("Client processed %d responses out of %d payloads.", responseCount, numPayloads)

	// 5. Verify received requests
	receivedRequests := make([]RequestData, 0)
	receivedCount := 0
	for req := range receivedDataChan {
		receivedCount++
		receivedRequests = append(receivedRequests, req)
	}

	t.Logf("Server received %d total requests, %d captured for analysis", receivedCount, len(receivedRequests))

	// 6. Check for specific header payloads in the requests
	headerChecks := map[string]bool{
		"X-Original-URL":          false,
		"X-Rewrite-URL":           false,
		"X-Forwarded-For":         false,
		"X-Middleware-Subrequest": false,
	}

	for _, req := range receivedRequests {
		// Convert the full request to lowercase for case-insensitive checking
		lowerRequest := strings.ToLower(req.FullRequest)

		// Check for presence of known headers
		for header := range headerChecks {
			if strings.Contains(lowerRequest, strings.ToLower(header)) {
				headerChecks[header] = true
				// Print details about the detected header
				t.Logf("Found header %s in request with URI: %s", header, req.URI)
			}
		}

		// Special case for CVE-2025-29927 (x-middleware-subrequest)
		if strings.Contains(lowerRequest, "x-middleware-subrequest") {
			// Check if the value contains the expected pattern (middleware:middleware...)
			if strings.Contains(lowerRequest, "middleware:middleware") {
				t.Logf("Found CVE-2025-29927 pattern in request: %s", req.URI)
			}
		}
	}

	// Verify we found at least some of the expected headers
	foundHeaders := 0
	for header, found := range headerChecks {
		if found {
			foundHeaders++
		} else {
			t.Logf("Warning: Did not find any requests with header: %s", header)
		}
	}

	if foundHeaders == 0 {
		t.Error("Failed to detect any of the expected headers in the requests")
	} else {
		t.Logf("Successfully detected %d/%d expected header types", foundHeaders, len(headerChecks))
	}

	// 7. Detailed analysis of a sample request if needed
	if len(receivedRequests) > 0 {
		sampleRequest := receivedRequests[0]
		t.Logf("Sample request URI: %s", sampleRequest.URI)
		t.Logf("Sample request headers and body: \n%s",
			strings.Join(strings.Split(sampleRequest.FullRequest, "\n")[1:], "\n"))
	}
}
