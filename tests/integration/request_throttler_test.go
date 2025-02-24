package tests

import (
	"net"
	"testing"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

// TestHTTPClient_Throttler tests the throttler functionality
func TestHTTPClient_Throttler(t *testing.T) {
	// Create a test server that returns 429 Too Many Requests
	server := fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			ctx.SetStatusCode(fasthttp.StatusTooManyRequests)
		},
	}
	defer server.Shutdown()

	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	go server.Serve(ln)

	opts := rawhttp.DefaultHTTPClientOptions()

	opts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	// Create a new HTTP client with the modified options
	client := rawhttp.NewHTTPClient(opts)

	// Send multiple requests to the test server
	for i := 0; i < 5; i++ {
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseRequest(req)
		defer fasthttp.ReleaseResponse(resp)

		req.SetRequestURI("http://inmemory")
		req.Header.SetMethod(fasthttp.MethodGet)

		// Execute the request
		_, err := client.DoRequest(req, resp, payload.BypassPayload{})
		if err != nil {
			t.Logf("Request %d failed: %v", i+1, err)
		}

		// Check if the throttler is active after the first 429 response
		if i > 0 && !client.IsThrottlerActive() {
			t.Errorf("Expected throttler to be active after 429 response, but it is not")
		}
	}

	// Verify that the throttler is active
	if !client.IsThrottlerActive() {
		t.Error("Expected throttler to be active, but it is not")
	}

	// Disable the throttler and verify
	client.DisableThrottler()
	if client.IsThrottlerActive() {
		t.Error("Expected throttler to be disabled, but it is still active")
	}
}
