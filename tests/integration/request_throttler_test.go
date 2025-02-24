package tests

import (
	"math"
	"net"
	"sync"
	"testing"
	"time"

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
	opts.AutoThrottle = true
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

func TestHTTPClient_Throttler2(t *testing.T) {
	var requestTimes []time.Time
	var mu sync.Mutex

	server := fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			mu.Lock()
			requestTimes = append(requestTimes, time.Now())
			mu.Unlock()
			ctx.SetStatusCode(fasthttp.StatusTooManyRequests)
		},
	}
	defer server.Shutdown()

	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	go server.Serve(ln)

	opts := rawhttp.DefaultHTTPClientOptions()
	opts.AutoThrottle = true
	opts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	client := rawhttp.NewHTTPClient(opts)

	// First request - should be immediate (no throttling yet)
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://inmemory")
	req.Header.SetMethod(fasthttp.MethodGet)

	t0 := time.Now()
	_, err := client.DoRequest(req, resp, payload.BypassPayload{})
	if err != nil {
		t.Fatalf("First request failed: %v", err)
	}
	if time.Since(t0) > 100*time.Millisecond {
		t.Error("First request shouldn't be throttled")
	}

	// Subsequent requests should be throttled
	for i := 1; i < 5; i++ {
		before := time.Now()
		_, err := client.DoRequest(req, resp, payload.BypassPayload{})
		if err != nil {
			t.Fatalf("Request %d failed: %v", i+1, err)
		}
		gap := time.Since(before)
		t.Logf("Request %d took: %v", i+1, gap)

		// Check against minimum delay (base - 20% jitter)
		minDelay := 160 * time.Millisecond // 200ms - (200ms * 0.2)
		if gap < minDelay {
			t.Errorf("Request %d was too fast (below min throttle+jitter). Took: %v, Expected >= %v",
				i+1, gap, minDelay)
		}
	}
}

func TestHTTPClient_ThrottlerMaxDelay(t *testing.T) {
	var requestTimes []time.Time
	var mu sync.Mutex

	server := fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			mu.Lock()
			requestTimes = append(requestTimes, time.Now())
			mu.Unlock()
			ctx.SetStatusCode(fasthttp.StatusTooManyRequests)
		},
	}
	defer server.Shutdown()

	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	go server.Serve(ln)

	opts := rawhttp.DefaultHTTPClientOptions()
	opts.AutoThrottle = true
	opts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	client := rawhttp.NewHTTPClient(opts)

	// Update throttler with new config directly
	client.GetThrottler().UpdateThrottlerConfig(&rawhttp.ThrottleConfig{
		BaseRequestDelay:        1000 * time.Millisecond,
		MaxRequestDelay:         5000 * time.Millisecond,
		ExponentialRequestDelay: 2.0,
		RequestDelayJitter:      20,
		ThrottleOnStatusCodes:   []int{429, 503, 507},
	})

	// First request - should be immediate (no throttling yet)
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://inmemory")
	req.Header.SetMethod(fasthttp.MethodGet)

	t0 := time.Now()
	_, err := client.DoRequest(req, resp, payload.BypassPayload{})
	if err != nil {
		t.Fatalf("First request failed: %v", err)
	}
	if time.Since(t0) > 100*time.Millisecond {
		t.Error("First request shouldn't be throttled")
	}

	// Subsequent requests should be throttled with exponential backoff
	for i := 1; i < 5; i++ {
		before := time.Now()
		_, err := client.DoRequest(req, resp, payload.BypassPayload{})
		if err != nil {
			t.Fatalf("Request %d failed: %v", i+1, err)
		}
		gap := time.Since(before)
		t.Logf("Request %d took: %v", i+1, gap)

		// Expected delay with exponential backoff: baseDelay * (2.0 ^ i)
		expectedBase := time.Duration(float64(1000*time.Millisecond) * math.Pow(2.0, float64(i-1)))
		if expectedBase > 5000*time.Millisecond {
			expectedBase = 5000 * time.Millisecond
		}

		// Allow for jitter
		minDelay := expectedBase
		maxDelay := expectedBase + time.Duration(float64(expectedBase)*0.2)

		if gap < minDelay || gap > maxDelay {
			t.Errorf("Request %d delay outside expected range. Got: %v, Expected: %v-%v",
				i+1, gap, minDelay, maxDelay)
		}
	}
}
