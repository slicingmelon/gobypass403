package rawhttp

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
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

	// Store raw request for verification
	var rawRequest []byte
	var mu sync.Mutex

	serverReady := make(chan struct{})
	serverErr := make(chan error, 1)

	// Setup test server that echoes back raw request
	s := &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			mu.Lock()
			defer mu.Unlock()

			// Get the raw request directly from ctx.Request (pointer)
			req := &ctx.Request

			// Build raw request string from the original request
			rawReq := fmt.Sprintf("%s %s HTTP/1.1\r\n%s",
				req.Header.Method(),
				req.RequestURI(),
				req.Header.String())

			// Store for verification (without copying the Request)
			rawRequest = []byte(rawReq)

			fmt.Printf(`
=== Raw Request ===
%s
================
`, rawReq)

			// Echo back exactly what we received
			ctx.Write(rawRequest)
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
	client := &Client{
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
			bypassModule: "header_ip",
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

				logger.EnableDebug()
				logger.EnableVerbose()
				req := fasthttp.AcquireRequest()
				resp := fasthttp.AcquireResponse()
				defer fasthttp.ReleaseRequest(req)
				defer fasthttp.ReleaseResponse(resp)

				rb.BuildRequest(req, job)

				// Build virtual request
				virtualReq := fmt.Sprintf("%s %s HTTP/1.1\r\n", job.Method, job.RawURI)
				for _, h := range job.Headers {
					virtualReq += fmt.Sprintf("%s: %s\r\n", h.Header, h.Value)
				}
				virtualReq += fmt.Sprintf("X-GB403-Debug: %s\r\n", job.PayloadSeed)
				virtualReq += "Connection: keep-alive\r\n\r\n"

				// Send request and let server handle the comparison printing
				if err := client.client.Do(req, resp); err != nil {
					t.Fatalf("Job %d failed: %v", i, err)
				}

				mu.Lock()
				echoedRequest := make([]byte, len(rawRequest))
				copy(echoedRequest, rawRequest)
				mu.Unlock()

				// Log only on failure to reduce output
				if !bytes.Contains(echoedRequest, []byte(job.Method+" "+job.RawURI)) {
					t.Logf("\nPayload %d Raw Request:\n%s", i, string(echoedRequest))
					t.Errorf("Request line mismatch for job %d", i)
				}

				// Verify all headers are present
				for _, header := range job.Headers {
					expectedHeader := fmt.Sprintf("%s: %s", header.Header, header.Value)
					if !bytes.Contains(echoedRequest, []byte(expectedHeader)) {
						// Print more debug info
						fmt.Printf("\nExpected header not found: %s\n", expectedHeader)
						fmt.Printf("Headers in request:\n%s\n", string(echoedRequest))
						t.Errorf("Missing header in job %d: %s", i, expectedHeader)
					}
				}

				// Verify debug header
				if !bytes.Contains(echoedRequest, []byte("X-GB403-Debug: "+job.PayloadSeed)) {
					t.Errorf("Missing or incorrect debug header in job %d", i)
				}
			}
		})
	}
}
