package rawhttp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
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
	client := &HttpClient{
		client: &fasthttp.Client{
			Dial: func(addr string) (net.Conn, error) {
				return ln.Dial()
			},
			MaxIdleConnDuration: time.Second,
			ReadTimeout:         time.Second,
			WriteTimeout:        time.Second,
		},
		options: DefaultOptionsSameHost(),
	}

	rb := NewRequestBuilder(client)

	// Test cases using real payload generators
	testCases := []struct {
		name         string
		targetURL    string
		bypassModule string
		generator    func(string, string) []payload.PayloadJob
	}{
		{
			name:         "HeaderIP Payloads",
			targetURL:    "http://example.com/test",
			bypassModule: "http_headers_ip",
			generator: func(url, module string) []payload.PayloadJob {
				return payload.GenerateHeaderIPJobs(url, module, "", "")
			},
		},
		{
			name:         "MidPaths Payloads",
			targetURL:    "http://example.com/test/path",
			bypassModule: "mid_paths",
			generator:    payload.GenerateMidPathsJobs,
		},
		{
			name:         "HeaderScheme Payloads",
			targetURL:    "http://example.com/admin",
			bypassModule: "header_scheme",
			generator:    payload.GenerateHeaderSchemeJobs,
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

			jobs := tc.generator(tc.targetURL, tc.bypassModule)
			if len(jobs) == 0 {
				t.Fatalf("No payloads generated for %s", tc.name)
			}

			for i, job := range jobs {
				select {
				case <-ctx.Done():
					t.Fatal("Test timeout")
				default:
				}

				GB403Logger.EnableDebug()
				GB403Logger.EnableVerbose()

				req := fasthttp.AcquireRequest()
				resp := fasthttp.AcquireResponse()
				defer fasthttp.ReleaseRequest(req)
				defer fasthttp.ReleaseResponse(resp)

				rb.BuildRequest(req, job)

				// Build virtual request
				GB403Logger.LogYellow("[GB403Logger] Sending request :\n%s", req)

				// Send request and let server handle the comparison printing
				if err := client.client.Do(req, resp); err != nil {
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
	client := &HttpClient{
		client: &fasthttp.Client{
			Dial: func(addr string) (net.Conn, error) {
				return ln.Dial()
			},
			MaxIdleConnDuration: time.Second,
			ReadTimeout:         time.Second,
			WriteTimeout:        time.Second,
		},
		options: DefaultOptionsSameHost(),
	}

	rb := NewRequestBuilder(client)

	// Test cases using real payload generators
	testCases := []struct {
		name         string
		targetURL    string
		bypassModule string
		generator    func(string, string) []payload.PayloadJob
	}{
		{
			name:         "MidPaths Payloads",
			targetURL:    "http://example.com/admin",
			bypassModule: "mid_paths",
			generator:    payload.GenerateMidPathsJobs,
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

			jobs := tc.generator(tc.targetURL, tc.bypassModule)
			if len(jobs) == 0 {
				t.Fatalf("No payloads generated for %s", tc.name)
			}

			for i, job := range jobs {
				select {
				case <-ctx.Done():
					t.Fatal("Test timeout")
				default:
				}

				GB403Logger.EnableDebug()
				GB403Logger.EnableVerbose()

				req := fasthttp.AcquireRequest()
				resp := fasthttp.AcquireResponse()
				defer fasthttp.ReleaseRequest(req)
				defer fasthttp.ReleaseResponse(resp)

				rb.BuildRequest(req, job)

				// Build virtual request
				GB403Logger.LogGreen("[GB403Logger][RequestBuilder] [X-GB403-Token: %s] Sending request: %s\n================>\n%s<================\n", job.PayloadToken, job.FullURL, req)

				// Send request and let server handle the comparison printing
				if err := client.client.Do(req, resp); err != nil {
					t.Fatalf("Job %d failed: %v", i, err)
				}

				GB403Logger.LogYellow("[GB403Logger] [X-GB403-Token: %s] Response received for: %s\n%s", job.PayloadToken, job.FullURL, resp.Body())
			}
		})
	}
}
