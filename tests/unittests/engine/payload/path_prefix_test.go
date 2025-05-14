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

func TestPathPrefixPayloads(t *testing.T) {
	startTime := time.Now()
	t.Logf("TestPathPrefixPayloads started at: %s", startTime.Format(time.RFC3339Nano))

	baseTargetURL := "http://localhost/admin/config" // Target URL with multiple segments
	moduleName := "path_prefix"

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
		TargetURL:    targetURL,
		BypassModule: moduleName,
	})
	generatedPayloads := pg.GeneratePathPrefixPayloads(targetURL, moduleName)
	if len(generatedPayloads) == 0 {
		t.Fatal("No payloads were generated, test cannot proceed")
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

	// Update payload destinations to use the actual server address
	for i := range generatedPayloads {
		generatedPayloads[i].Scheme = "http"
		generatedPayloads[i].Host = serverAddr
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

	// Send Requests using RequestWorkerPool
	clientSendStartTime := time.Now()
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Timeout = 3 * time.Second
	clientOpts.MaxRetries = 0
	clientOpts.MaxConsecutiveFailedReqs = numPayloads + 10 // Allow for all payloads to fail

	// Use a reasonable number of workers for local testing
	wp := rawhttp.NewRequestWorkerPool(clientOpts, 100)
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

	// Verify Received URIs
	verificationStartTime := time.Now()
	receivedURIsHex := make(map[string]struct{})
	literalSpaceFound := false
	receivedCount := len(collectedRequests)

	for _, reqData := range collectedRequests {
		if strings.Contains(reqData.URI, " ") {
			t.Errorf("Literal space '\x20' found in received URI path: '%s' (Hex: %s)", reqData.URI, hex.EncodeToString([]byte(reqData.URI)))
			literalSpaceFound = true
		}

		hexURI := hex.EncodeToString([]byte(reqData.URI))
		receivedURIsHex[hexURI] = struct{}{}
	}

	t.Logf("Server received %d total requests, %d unique URIs", receivedCount, len(receivedURIsHex))

	// Comparison
	if len(expectedURIsHex) != len(receivedURIsHex) {
		t.Errorf("Mismatch in count for %s: Expected %d unique URIs, Server received %d unique URIs",
			moduleName, len(expectedURIsHex), len(receivedURIsHex))

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
			t.Errorf("URIs expected but not received by server for %s:\n%s", moduleName, strings.Join(missing, "\n"))
		}
		if len(extra) > 0 {
			t.Errorf("URIs received by server but not expected for %s:\n%s", moduleName, strings.Join(extra, "\n"))
		}
	} else {
		// If counts match, verify all expected URIs were received
		match := true
		for hexExp := range expectedURIsHex {
			if _, found := receivedURIsHex[hexExp]; !found {
				rawBytes, _ := hex.DecodeString(hexExp)
				t.Errorf("Expected URI not received by server for %s: '%s' (Hex: %s)", moduleName, string(rawBytes), hexExp)
				match = false
			}
		}
		if match {
			t.Logf("Successfully verified %d unique received URIs against expected URIs for %s.", len(receivedURIsHex), moduleName)
		}
	}

	// Final check on the literal space flag
	if literalSpaceFound {
		t.Error("Test concluded with errors: Literal spaces were found in URI paths.")
	}

	t.Logf("Verification finished. (took %s)", time.Since(verificationStartTime))
	t.Logf("TestPathPrefixPayloads finished. Total time: %s", time.Since(startTime))
}

func TestPathPrefixPayloadsWithProxy(t *testing.T) {
	//targetURL := "http://localhost/admin/config" // Target URL with multiple segments
	targetURL := "http://localhost/admin" // Target URL with multiple segments
	moduleName := "path_prefix"
	proxyURL := "http://127.0.0.1:8080"

	t.Logf("--- Starting TestPathPrefixPayloadsWithProxy (%s) --- Proxy: %s ---", moduleName, proxyURL)

	// 1. Generate Payloads
	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: moduleName,
	})
	generatedPayloads := pg.GeneratePathPrefixPayloads(targetURL, moduleName)
	if len(generatedPayloads) == 0 {
		t.Fatal("(WithProxy) No payloads were generated")
	}
	numPayloads := len(generatedPayloads)
	t.Logf("(WithProxy) Generated %d payloads for %s.", numPayloads, moduleName)

	// 2. Create channel for server results
	receivedDataChan := make(chan RequestData, numPayloads)

	// 3. Start the server
	serverAddr, stopServer := startRawTestServer(t, receivedDataChan)
	defer stopServer()

	// 4. Update payload destinations
	for i := range generatedPayloads {
		generatedPayloads[i].Scheme = "http"
		generatedPayloads[i].Host = serverAddr // The client will send this to the proxy, proxy forwards to this.
	}

	// Prepare expected URIs map (hex-encoded)
	expectedURIsHex := make(map[string]struct{})
	for _, p := range generatedPayloads {
		hexURI := hex.EncodeToString([]byte(p.RawURI))
		expectedURIsHex[hexURI] = struct{}{}
	}
	if len(expectedURIsHex) != numPayloads {
		t.Logf("(WithProxy) Warning: Number of unique expected URIs (%d) differs from total generated payloads (%d).", len(expectedURIsHex), numPayloads)
	}

	// 5. Send Requests with Proxy
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Timeout = 20 * time.Second // Increased timeout when proxy is involved
	clientOpts.MaxRetries = 0
	clientOpts.MaxConsecutiveFailedReqs = numPayloads + 100
	clientOpts.ProxyURL = proxyURL                 // Key change: Set the proxy
	clientOpts.RequestDelay = 5 * time.Millisecond // Added delay between requests

	t.Logf("(WithProxy) Client configured to use proxy: %s, Timeout: %s, RequestDelay: %s", clientOpts.ProxyURL, clientOpts.Timeout, clientOpts.RequestDelay)

	wp := rawhttp.NewRequestWorkerPool(clientOpts, 150)
	resultsChan := wp.ProcessRequests(generatedPayloads)

	// 6. Drain client results
	responseCount := 0      // This counts actual responses received via the proxy
	for range resultsChan { // We don't need to inspect 'result' here for errors, as RawHTTPResponseDetails has no error field.
		responseCount++ // Client-side transport/proxy errors will result in fewer responses than payloads.
	}
	wp.Close()
	t.Logf("(WithProxy) Client processed %d responses through proxy.", responseCount)

	// 7. Close Server's Results Channel
	time.Sleep(500 * time.Millisecond) // Slightly longer wait with proxy
	close(receivedDataChan)

	// 8. Verify Received URIs & Check for literal spaces
	receivedRawURIs := []string{}
	literalSpaceFoundInProxyTest := false
	for reqData := range receivedDataChan {
		receivedRawURIs = append(receivedRawURIs, reqData.URI)
		if strings.Contains(reqData.URI, " ") {
			t.Errorf("(WithProxy) Literal space '\x20' found in received URI path: '%s' (Hex: %s)", reqData.URI, hex.EncodeToString([]byte(reqData.URI)))
			literalSpaceFoundInProxyTest = true
		}
	}

	if literalSpaceFoundInProxyTest {
		t.Log("(WithProxy) Test potentially failed due to literal spaces found in received URI paths via proxy.")
	}

	receivedURIsHex := make(map[string]struct{})
	for _, rawURI := range receivedRawURIs {
		hexURI := hex.EncodeToString([]byte(rawURI))
		receivedURIsHex[hexURI] = struct{}{}
	}

	// 9. Comparison
	expectedCount := len(expectedURIsHex)
	receivedCountViaProxy := len(receivedURIsHex)

	t.Logf("(WithProxy) Expected %d unique URIs. Received %d unique URIs via proxy.", expectedCount, receivedCountViaProxy)

	if expectedCount != receivedCountViaProxy {
		t.Errorf("(WithProxy) Mismatch in unique URI count: Expected %d, Server received %d via proxy", expectedCount, receivedCountViaProxy)
		// Detailed missing/extra logic (same as before, with (WithProxy) prefix)
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
			t.Errorf("(WithProxy) URIs expected but not received by server (%d missing):\n%s", len(missing), strings.Join(missing, "\n"))
		}
		if len(extra) > 0 {
			t.Errorf("(WithProxy) URIs received by server but not expected (%d extra):\n%s", len(extra), strings.Join(extra, "\n"))
		}
	}

	// Final check
	if literalSpaceFoundInProxyTest {
		t.Error("(WithProxy) Test concluded with errors: Literal spaces WERE FOUND in URI paths when using proxy.")
	}
	if responseCount < numPayloads {
		t.Logf("(WithProxy) Warning: Not all requests were processed by the client (%d/%d). This likely indicates issues connecting to or communicating with the proxy at %s.", responseCount, numPayloads, proxyURL)
	}
	if receivedCountViaProxy < expectedCount {
		t.Logf("(WithProxy) Warning: Not all expected URIs were received by the test server (%d/%d). Ensure proxy is running and forwarding correctly.", receivedCountViaProxy, expectedCount)
	}

	if !literalSpaceFoundInProxyTest && expectedCount == receivedCountViaProxy && responseCount == numPayloads {
		t.Log("(WithProxy) Test passed: All URI paths correctly received via proxy without literal spaces, counts match, and all requests processed.")
	} else {
		t.Log("(WithProxy) Test finished. Review logs for failures or warnings related to spaces, URI mismatches, or proxy connectivity.")
		if !literalSpaceFoundInProxyTest && expectedCount == receivedCountViaProxy {
			// If spaces are not an issue and URIs match, but responseCount is low, it's a proxy comms issue mostly.
			t.Log("(WithProxy) Note: No literal spaces detected and URI sets matched, but request processing count was low. Primarily a proxy communication/forwarding test concern.")
		}
		// The test will be marked as failed by t.Error or t.Errorf if critical issues were found.
	}
}
