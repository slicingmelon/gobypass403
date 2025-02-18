package tests

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp"

	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func TestRequestBuilderViaEchoServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	// Create listener with context for cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	var mu sync.Mutex

	serverReady := make(chan struct{})
	serverErr := make(chan error, 1)

	// Setup test server that echoes back raw request
	s := &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			mu.Lock()
			defer mu.Unlock()

			ctxLogger := ctx.Logger()
			ctxLogger.Printf("[ctxLogger]Request received!")
			// Get the raw request directly from ctx.Request (pointer)
			req := &ctx.Request
			reqHeader := &ctx.Request.Header

			fmt.Fprintf(ctx, "Raw request is:\n==>\n%s\n<==\n", req)

			ctx.Success("text/html", []byte(fmt.Sprintf("requestURI=%s, body=%s", reqHeader.RequestURI(), req.Body())))

		},
		ReadTimeout:                   5 * time.Second,
		WriteTimeout:                  5 * time.Second,
		DisableHeaderNamesNormalizing: true,
	}

	// Start server with proper error handling
	go func() {
		close(serverReady)
		if err := s.Serve(ln); err != nil {
			select {
			case serverErr <- err:
			default:
			}
		}
	}()

	<-serverReady // Wait for server to start

	// Create test client with custom dialer
	clientoptions := rawhttp.DefaultHTTPClientOptions()
	clientoptions.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}
	client := rawhttp.NewHTTPClient(clientoptions)

	// Test cases using real payload generators
	testCases := []struct {
		name         string
		targetURL    string
		bypassModule string
		generator    func(pg *payload.PayloadGenerator, url, module string) []payload.BypassPayload
	}{
		{
			name:         "HeaderIP Payloads",
			targetURL:    "http://example.com/test",
			bypassModule: "http_headers_ip",
			generator: func(pg *payload.PayloadGenerator, url, module string) []payload.BypassPayload {
				return pg.GenerateHeaderIPPayloads(url, module, "", "")
			},
		},
		{
			name:         "MidPaths Payloads",
			targetURL:    "http://example.com/test/path",
			bypassModule: "mid_paths",
			generator: func(pg *payload.PayloadGenerator, url, module string) []payload.BypassPayload {
				return pg.GenerateMidPathsPayloads(url, module)
			},
		},
		{
			name:         "HeaderScheme Payloads",
			targetURL:    "http://example.com/admin",
			bypassModule: "header_scheme",
			generator: func(pg *payload.PayloadGenerator, url, module string) []payload.BypassPayload {
				return pg.GenerateHeaderSchemePayloads(url, module)
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			select {
			case err := <-serverErr:
				t.Fatalf("Server error: %v", err)
			default:
			}

			pg := payload.NewPayloadGenerator()
			jobs := tc.generator(pg, tc.targetURL, tc.bypassModule)
			if len(jobs) == 0 {
				t.Fatalf("No payloads generated for %s", tc.name)
			}

			for i, job := range jobs {
				select {
				case <-ctx.Done():
					t.Fatal("Test timeout")
				default:
				}

				GB403Logger.DefaultLogger.EnableDebug()
				GB403Logger.DefaultLogger.EnableVerbose()

				req := fasthttp.AcquireRequest()
				resp := fasthttp.AcquireResponse()
				defer fasthttp.ReleaseRequest(req)
				defer fasthttp.ReleaseResponse(resp)

				rawhttp.BuildRawHTTPRequest(client, req, job)

				// Build virtual request
				GB403Logger.PrintYellow("[GB403Logger] Sending request :\n%s", req)

				// Send request and let server handle the comparison printing
				_, err := client.DoRequest(req, resp, payload.BypassPayload{})
				if err != nil {
					t.Fatalf("Job %d failed: %v", i, err)
				}

				// // Log only on failure to reduce output
				// if !bytes.Contains(echoedRequest, []byte(job.Method+" "+job.RawURI)) {
				// 	t.Logf("\nPayload %d Raw Request:\n%s", i, string(echoedRequest))
				// 	t.Errorf("Request line mismatch for job %d", i)
				// }

				// // Verify all headers are present
				// for _, header := range job.Headers {
				// 	expectedHeader := fmt.Sprintf("%s: %s", header.Header, header.Value)
				// 	if !bytes.Contains(echoedRequest, []byte(expectedHeader)) {
				// 		// Print more debug info
				// 		fmt.Printf("\nExpected header not found: %s\n", expectedHeader)
				// 		fmt.Printf("Headers in request:\n%s\n", string(echoedRequest))
				// 		t.Errorf("Missing header in job %d: %s", i, expectedHeader)
				// 	}
				// }

				// // Verify debug header
				// if !bytes.Contains(echoedRequest, []byte("X-GB403-Debug: "+job.PayloadSeed)) {
				// 	t.Errorf("Missing or incorrect debug header in job %d", i)

			}
		})
	}
}

func TestRequestBuilderMidPathsPayloads(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	// Create listener with context for cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	var mu sync.Mutex

	serverReady := make(chan struct{})
	serverErr := make(chan error, 1)

	// Setup test server that echoes back raw request
	s := &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			mu.Lock()
			defer mu.Unlock()

			ctx.Request.URI().DisablePathNormalizing = true

			//ctxLogger := ctx.Logger()

			// Get the raw request directly from ctx.Request (pointer)
			incomingRequest := &ctx.Request
			//incomingRequestHeader := &ctx.Request.Header

			incomingRequest.URI().DisablePathNormalizing = true

			//ctxLogger.Printf("[ctxLogger] Request received!")
			// Combine both outputs in the response
			responseText := fmt.Sprintf(
				"[fasthttpServer] How I receved the request:\n================\n%s\n<================\nrequestURI=%s, body=%s\n<================",
				incomingRequest,
				incomingRequest.URI().RequestURI(),
				incomingRequest.Body(),
			)
			ctx.Success("text/html", []byte(responseText))
		},
		ReadTimeout:                   5 * time.Second,
		WriteTimeout:                  5 * time.Second,
		DisableHeaderNamesNormalizing: true,
	}

	// Start server with proper error handling
	go func() {
		close(serverReady)
		if err := s.Serve(ln); err != nil {
			select {
			case serverErr <- err:
			default:
			}
		}
	}()

	<-serverReady

	// Create test client with custom dialer
	clientoptions := rawhttp.DefaultHTTPClientOptions()
	clientoptions.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}
	client := rawhttp.NewHTTPClient(clientoptions)

	// Test cases using real payload generators
	testCases := []struct {
		name         string
		targetURL    string
		bypassModule string
		generator    func(pg *payload.PayloadGenerator, url, module string) []payload.BypassPayload
	}{
		{
			name:         "MidPaths Payloads",
			targetURL:    "http://example.com/admin",
			bypassModule: "mid_paths",
			generator: func(pg *payload.PayloadGenerator, url, module string) []payload.BypassPayload {
				return pg.GenerateMidPathsPayloads(url, module)
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			select {
			case err := <-serverErr:
				t.Fatalf("Server error: %v", err)
			default:
			}

			pg := payload.NewPayloadGenerator()
			jobs := tc.generator(pg, tc.targetURL, tc.bypassModule)
			if len(jobs) == 0 {
				t.Fatalf("No payloads generated for %s", tc.name)
			}

			for i, job := range jobs {
				select {
				case <-ctx.Done():
					t.Fatal("Test timeout")
				default:
				}

				GB403Logger.DefaultLogger.EnableDebug()
				GB403Logger.DefaultLogger.EnableVerbose()

				req := fasthttp.AcquireRequest()
				resp := fasthttp.AcquireResponse()
				defer fasthttp.ReleaseRequest(req)
				defer fasthttp.ReleaseResponse(resp)

				rawhttp.BuildRawHTTPRequest(client, req, job)

				// Build virtual request
				GB403Logger.PrintGreen("[GB403Logger][RequestBuilder] [X-GB403-Token: %s] Sending request: %s\n================>\n%s<================\n", job.PayloadToken, payload.BypassPayloadToFullURL(job), req)

				// Send request and let server handle the comparison printing
				if _, err := client.DoRequest(req, resp, job); err != nil {
					t.Fatalf("Job %d failed: %v", i, err)
				}

				GB403Logger.PrintYellow("[GB403Logger] [X-GB403-Token: %s] Response received for: %s\n%s", job.PayloadToken, payload.BypassPayloadToFullURL(job), resp.Body())
			}
		})
	}
}

func TestRequestBuilderHostHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	clientOpts := rawhttp.DefaultHTTPClientOptions()

	client := rawhttp.NewHTTPClient(clientOpts)
	//rb := NewRequestBuilder(client, _logger)

	testCases := []struct {
		name string
		url  string
	}{
		// {
		// 	name: "Basic GET Request",
		// 	url:  "http://httpbin.org/get",
		// },
		{
			name: "HTTPS GET Request",
			url:  "https://example.com",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := client.AcquireRequest()
			resp := client.AcquireResponse()
			defer client.ReleaseRequest(req)
			defer client.ReleaseResponse(resp)

			// Create minimal payload job with just Method and FullURL
			job := payload.BypassPayload{
				Method: "GET",
				Host:   "google.com",
				RawURI: tc.url,
				Headers: []payload.Headers{
					{Header: "Host", Value: "yahoo.com"},
				},
			}
			req.UseHostHeader = false
			req.Header.SetMethod(job.Method)
			req.SetRequestURI(payload.BypassPayloadToFullURL(job))
			req.URI().DisablePathNormalizing = true
			req.Header.DisableNormalizing()
			req.Header.SetNoDefaultContentType(true)

			for _, h := range job.Headers {
				if h.Header == "Host" {
					req.UseHostHeader = true
					req.Header.Set(h.Header, h.Value)
				}
			}

			GB403Logger.PrintGreen("\n=== Sending Request ===")
			GB403Logger.PrintYellow("Test Case: %s", tc.name)
			GB403Logger.PrintYellow("Request URI: %s", req.URI().FullURI())
			GB403Logger.PrintYellow("===================\n")

			if _, err := client.DoRequest(req, resp, job); err != nil {
				t.Fatalf("Request failed: %v", err)
			}

			// Verify response
			statusCode := resp.StatusCode()
			GB403Logger.PrintGreen("Response Status Code: %d", statusCode)
		})
	}
}

func TestResponseProcessingWithSpacedHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	// Create test server
	handler := func(ctx *fasthttp.RequestCtx) {
		testCase := string(ctx.Request.Header.Peek("X-Test-Case"))
		switch testCase {
		case "content-disposition":
			ctx.Response.Header.Set("Content-Disposition", "attachment; filename=\"test file.pdf\"")
			ctx.Response.Header.Set("Content-Type", "application/pdf")
			ctx.SetStatusCode(200)
			ctx.SetBody([]byte("PDF content with special chars: áéíóú"))
		case "csp-header":
			ctx.Response.Header.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://example.com")
			ctx.Response.Header.Set("Content-Type", "text/html; charset=utf-8")
			ctx.SetStatusCode(200)
			ctx.SetBody([]byte("<html><head><title>Test Page</title></head><body>Test content with spaces and special chars: áéíóú</body></html>"))
		case "malformed-response":
			// Test case for malformed response
			ctx.Response.SetBodyString("nction() {\n\treturn this.href")
			ctx.Response.Header.SetContentType("text/html")
			ctx.SetStatusCode(200)
		}
	}

	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	s := &fasthttp.Server{
		Handler:                       handler,
		DisableHeaderNamesNormalizing: true,
	}
	go s.Serve(ln) //nolint:errcheck

	clientoptions := rawhttp.DefaultHTTPClientOptions()
	clientoptions.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	client := rawhttp.NewHTTPClient(clientoptions)

	testCases := []struct {
		name           string
		testCaseID     string
		expectedResp   map[string]string
		expectedBody   string
		expectError    bool
		expectedStatus int
	}{
		{
			name:       "Content-Disposition with spaces",
			testCaseID: "content-disposition",
			expectedResp: map[string]string{
				"Content-Disposition": "attachment; filename=\"test file.pdf\"",
				"Content-Type":        "application/pdf",
			},
			expectedBody:   "PDF content with special chars: áéíóú",
			expectError:    false,
			expectedStatus: 200,
		},
		{
			name:       "CSP Header with spaces",
			testCaseID: "csp-header",
			expectedResp: map[string]string{
				"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://example.com",
				"Content-Type":            "text/html; charset=utf-8",
			},
			expectedBody:   "<html><head><title>Test Page</title></head><body>Test content with spaces and special chars: áéíóú</body></html>",
			expectError:    false,
			expectedStatus: 200,
		},
		{
			name:           "Malformed Response",
			testCaseID:     "malformed-response",
			expectedResp:   map[string]string{},
			expectedBody:   "nction() {\n\treturn this.href",
			expectError:    true,
			expectedStatus: 0, // Status code will be 0 for malformed responses
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := client.AcquireRequest()
			resp := client.AcquireResponse()
			defer client.ReleaseRequest(req)
			defer client.ReleaseResponse(resp)

			req.SetRequestURI("http://testserver/test")
			req.Header.SetMethod("GET")
			req.Header.Set("X-Test-Case", tc.testCaseID)

			respTime, err := client.DoRequest(req, resp, payload.BypassPayload{})
			if err != nil && !tc.expectError {
				t.Fatalf("Unexpected request error: %v", err)
			}

			// Get response headers
			headers := rawhttp.GetResponseHeaders(&resp.Header, resp.StatusCode(), []byte{})

			// Log response details for debugging
			GB403Logger.Info().Msgf("\n=== Response Details for %s ===\n", tc.name)
			GB403Logger.Info().Msgf("Response Time: %dms", respTime)
			GB403Logger.Info().Msgf("Status Code: %d", resp.StatusCode())
			GB403Logger.Info().Msgf("Headers:\n%s", string(headers))
			GB403Logger.Info().Msgf("Body:\n%s", string(resp.Body()))
			GB403Logger.Info().Msgf("================\n")

			if !tc.expectError {
				// Verify headers
				for header, expectedValue := range tc.expectedResp {
					if !bytes.Contains(headers, []byte(header+": "+expectedValue)) {
						t.Errorf("Header %s not found or incorrect\nExpected: %s\nGot: %s",
							header, expectedValue, string(headers))
					}
				}

				// Verify body
				if !bytes.Equal(resp.Body(), []byte(tc.expectedBody)) {
					t.Errorf("Body mismatch\nExpected: %s\nGot: %s",
						tc.expectedBody, string(resp.Body()))
				}

				if resp.StatusCode() != tc.expectedStatus {
					t.Errorf("Expected status code %d, got %d", tc.expectedStatus, resp.StatusCode())
				}
			}

		})
	}
}
