package tests

import (
	"encoding/hex"
	"fmt"
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

	// Update payload destinations and create expected request map
	expectedRequestsHex := make(map[string]struct{})
	for i := range generatedPayloads {
		// Ensure each payload has the correct server address
		generatedPayloads[i].Scheme = "http"
		generatedPayloads[i].Host = serverAddr

		// We're tracking the full raw HTTP request, so we need to construct a
		// predictable request to compare against what the server receives
		// This will be built from the URI and any headers that would be sent
		reqLine := fmt.Sprintf("%s %s HTTP/1.1\r\n", generatedPayloads[i].Method, generatedPayloads[i].RawURI)
		reqHost := fmt.Sprintf("Host: %s\r\n", serverAddr)
		reqHeaders := ""
		for _, h := range generatedPayloads[i].Headers {
			reqHeaders += fmt.Sprintf("%s: %s\r\n", h.Header, h.Value)
		}
		reqEnd := "\r\n" // Empty line to end headers

		predictedReq := reqLine + reqHost + reqHeaders + reqEnd
		hexReq := hex.EncodeToString([]byte(predictedReq))
		expectedRequestsHex[hexReq] = struct{}{}
	}
	t.Logf("Prepared %d unique expected request patterns for verification", len(expectedRequestsHex))

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
	t.Logf("Client processed %d responses out of %d payloads. (took %s to send and drain)", responseCount, numPayloads, time.Since(clientSendStartTime))

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

	// Verify Received Requests with comprehensive hex comparison
	verificationStartTime := time.Now()
	receivedRequestsHex := make(map[string]struct{})
	receivedCount := 0

	for _, reqData := range collectedRequests {
		receivedCount++
		// Use the HexEncoded field that contains the full raw HTTP request
		receivedRequestsHex[reqData.HexEncoded] = struct{}{}
	}

	t.Logf("Server received %d total requests, %d unique requests", receivedCount, len(receivedRequestsHex))

	// Perform comprehensive request comparison
	if len(expectedRequestsHex) != len(receivedRequestsHex) {
		t.Errorf("Mismatch in count: Expected %d unique requests, Server received %d unique requests",
			len(expectedRequestsHex), len(receivedRequestsHex))

		// Find missing/extra requests
		missing := []string{}
		for hexExp := range expectedRequestsHex {
			if _, found := receivedRequestsHex[hexExp]; !found {
				rawBytes, _ := hex.DecodeString(hexExp)
				missing = append(missing, fmt.Sprintf("'%s' (Hex: %s)", string(rawBytes), hexExp))
			}
		}

		extra := []string{}
		for hexRcv := range receivedRequestsHex {
			if _, found := expectedRequestsHex[hexRcv]; !found {
				rawBytes, _ := hex.DecodeString(hexRcv)
				extra = append(extra, fmt.Sprintf("'%s' (Hex: %s)", string(rawBytes), hexRcv))
			}
		}

		if len(missing) > 0 {
			if len(missing) > 5 {
				t.Errorf("%d expected requests not received. First 5 examples:", len(missing))
				for i := 0; i < 5 && i < len(missing); i++ {
					t.Errorf("Missing: %s", missing[i])
				}
			} else {
				t.Errorf("Requests expected but not received by server:\n%s", strings.Join(missing, "\n"))
			}
		}

		if len(extra) > 0 {
			if len(extra) > 5 {
				t.Errorf("%d unexpected requests received. First 5 examples:", len(extra))
				for i := 0; i < 5 && i < len(extra); i++ {
					t.Errorf("Extra: %s", extra[i])
				}
			} else {
				t.Errorf("Requests received by server but not expected:\n%s", strings.Join(extra, "\n"))
			}
		}
	} else {
		// If counts match, verify all expected requests were received
		mismatchCount := 0
		for hexExp := range expectedRequestsHex {
			if _, found := receivedRequestsHex[hexExp]; !found {
				mismatchCount++
				if mismatchCount <= 5 { // Limit output to first 5 mismatches
					rawBytes, _ := hex.DecodeString(hexExp)
					t.Errorf("Expected request not received: '%s' (Hex: %s)", string(rawBytes), hexExp)
				}
			}
		}

		if mismatchCount > 0 {
			t.Errorf("Total of %d expected requests not received", mismatchCount)
		} else {
			t.Logf("Successfully verified %d unique received requests against expected requests", len(receivedRequestsHex))
		}
	}

	t.Logf("Verification finished. (took %s)", time.Since(verificationStartTime))
	t.Logf("TestHeadersURLPayloads finished. Total time: %s", time.Since(startTime))
}
