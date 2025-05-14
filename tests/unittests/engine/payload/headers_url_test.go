package tests

import (
	"bufio"
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

	// Create a map to track which payloads have been verified
	payloadVerified := make(map[string]bool)
	for _, p := range generatedPayloads {
		payloadVerified[p.PayloadToken] = false
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

	// Process received requests for 1:1 verification
	verificationStartTime := time.Now()
	receivedCount := len(collectedRequests)
	t.Logf("Server received %d total requests for 1:1 verification", receivedCount)

	// Match each received request to its original payload by token
	verifiedCount := 0
	for _, reqData := range collectedRequests {
		// Extract debug token from request
		token := extractDebugToken(reqData.FullRequest)
		if token != "" && payloadVerified[token] == false {
			payloadVerified[token] = true
			verifiedCount++
		}
	}

	t.Logf("Verified %d/%d payloads with 1:1 matching", verifiedCount, numPayloads)

	// If not all payloads were verified, report error
	if verifiedCount < numPayloads {
		missingCount := numPayloads - verifiedCount
		t.Errorf("%d payloads were not verified (missing in received requests)", missingCount)

		// Show examples of unverified payloads
		if missingCount > 0 {
			examplesShown := 0
			for token, verified := range payloadVerified {
				if !verified && examplesShown < 5 {
					t.Errorf("Payload not verified: %s", token)
					examplesShown++
				}
			}
		}
	} else {
		t.Logf("Successfully verified all %d payloads were sent and received correctly", numPayloads)
	}

	t.Logf("Verification finished. (took %s)", time.Since(verificationStartTime))
	t.Logf("TestHeadersURLPayloads finished. Total time: %s", time.Since(startTime))
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
