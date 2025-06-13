package tests

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
	"github.com/slicingmelon/gobypass403/core/engine/rawhttp"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

func TestHeadersURLPayloads(t *testing.T) {
	// Enable debug mode to ensure debug tokens are included in requests
	GB403Logger.DefaultLogger.EnableDebug()
	//defer GB403Logger.SetDebugMode(false)

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

	// Create maps to track payloads and expected critical components
	payloadVerified := make(map[string]bool)
	payloadExpectedURI := make(map[string]string)       // token -> hex encoded URI
	payloadExpectedHeaders := make(map[string][]string) // token -> list of hex encoded "Header: Value" pairs

	// Store expected components for each payload
	for _, p := range generatedPayloads {
		token := p.PayloadToken
		payloadVerified[token] = false

		// Store the hex-encoded RawURI for comparison
		payloadExpectedURI[token] = hex.EncodeToString([]byte(p.RawURI))

		// Store hex-encoded custom headers
		headerList := make([]string, 0, len(p.Headers))
		for _, h := range p.Headers {
			headerStr := h.Header + ": " + h.Value
			headerHex := hex.EncodeToString([]byte(headerStr))
			headerList = append(headerList, headerHex)
		}
		payloadExpectedHeaders[token] = headerList
	}

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

	// Update payload destinations to use the actual server address
	for i := range generatedPayloads {
		generatedPayloads[i].Scheme = "http"
		generatedPayloads[i].Host = serverAddr
	}

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

	// Process received requests for 1:1 verification with hex comparison
	verificationStartTime := time.Now()
	receivedCount := len(collectedRequests)
	t.Logf("Server received %d total requests for 1:1 verification", receivedCount)

	// Detailed verification counters
	verifiedCount := 0
	uriMismatchCount := 0
	headersMismatchCount := 0

	// Track all hex mismatches for reporting
	uriMismatches := make([]string, 0)
	allHeaderMismatches := make([]string, 0)

	// Verify each request matches its corresponding payload
	for _, reqData := range collectedRequests {
		// Extract debug token from request
		token := extractDebugToken(reqData.FullRequest)
		if token == "" || payloadVerified[token] {
			continue // Skip if token not found or already verified
		}

		// First mark this payload as found
		payloadVerified[token] = true
		verifiedCount++

		// Now verify critical components using hex comparison

		// Check URI
		receivedURIHex := hex.EncodeToString([]byte(reqData.URI))
		expectedURIHex := payloadExpectedURI[token]

		if receivedURIHex != expectedURIHex {
			uriMismatchCount++
			if len(uriMismatches) < 5 { // Limit to 5 examples
				uriMismatches = append(uriMismatches,
					formatHexMismatch(token, "URI", expectedURIHex, receivedURIHex))
			}
		}

		// Check Headers
		expectedHeaders := payloadExpectedHeaders[token]
		headerMismatches := verifyHeaders(expectedHeaders, reqData.FullRequest)

		if len(headerMismatches) > 0 {
			headersMismatchCount++
			allHeaderMismatches = append(allHeaderMismatches, headerMismatches...)
		}
	}

	// Report verification results
	t.Logf("Verified %d/%d payloads with 1:1 matching", verifiedCount, numPayloads)

	// Report any missing payloads
	if verifiedCount < numPayloads {
		missingCount := numPayloads - verifiedCount
		t.Errorf("%d payloads were not received", missingCount)

		// Show examples of missing payloads
		missingExamples := 0
		for token, verified := range payloadVerified {
			if !verified && missingExamples < 5 {
				t.Errorf("Payload not received: %s", token)
				missingExamples++
			}
		}
	}

	// Report any URI mismatches
	if uriMismatchCount > 0 {
		t.Errorf("%d payloads had URI mismatches", uriMismatchCount)
		for _, mismatch := range uriMismatches {
			t.Errorf("%s", mismatch)
		}
	}

	// Report any header mismatches
	if headersMismatchCount > 0 {
		t.Errorf("%d payloads had header mismatches", headersMismatchCount)
		for _, mismatch := range allHeaderMismatches[:min(5, len(allHeaderMismatches))] {
			t.Errorf("%s", mismatch)
		}
	}

	// Overall success message
	if verifiedCount == numPayloads && uriMismatchCount == 0 && headersMismatchCount == 0 {
		t.Logf("Successfully verified all %d payloads were sent and received with exact content matching", numPayloads)
	}

	t.Logf("Verification finished. (took %s)", time.Since(verificationStartTime))
	t.Logf("TestHeadersURLPayloads finished. Total time: %s", time.Since(startTime))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// extractDebugToken extracts the debug token from a request
func extractDebugToken(requestStr string) string {
	scanner := bufio.NewScanner(strings.NewReader(requestStr))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.ToLower(line), "x-gb403-token:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// formatHexMismatch formats a hex mismatch for reporting
func formatHexMismatch(token, field, expected, received string) string {
	expBytes, _ := hex.DecodeString(expected)
	recvBytes, _ := hex.DecodeString(received)
	return fmt.Sprintf("Token %s: %s mismatch\n  Expected (hex): %s\n  Expected: %q\n  Received (hex): %s\n  Received: %q",
		token, field, expected, string(expBytes), received, string(recvBytes))
}

// verifyHeaders checks if all expected headers are present in the request
// Returns list of missing/mismatched headers
func verifyHeaders(expectedHeadersHex []string, fullRequest string) []string {
	mismatches := make([]string, 0)

	// Look for each expected header in the request
	for _, hexHeader := range expectedHeadersHex {
		headerBytes, _ := hex.DecodeString(hexHeader)
		headerStr := string(headerBytes)

		// Split header into name and value
		parts := strings.SplitN(headerStr, ":", 2)
		if len(parts) != 2 {
			continue // Malformed header
		}

		headerName := strings.TrimSpace(parts[0])
		headerValue := strings.TrimSpace(parts[1])

		// Check if this header+value exists in the request
		headerFound := false
		scanner := bufio.NewScanner(strings.NewReader(fullRequest))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(strings.ToLower(line), strings.ToLower(headerName+":")) {
				lineParts := strings.SplitN(line, ":", 2)
				if len(lineParts) == 2 && strings.TrimSpace(lineParts[1]) == headerValue {
					headerFound = true
					break
				}
			}
		}

		if !headerFound {
			mismatches = append(mismatches, fmt.Sprintf("Header not found or value mismatch: %s", headerStr))
		}
	}

	return mismatches
}
