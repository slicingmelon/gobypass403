package tests

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func TestClient301RedirectInmemory(t *testing.T) {
	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Setup redirect handler
	redirectHandler := func(ctx *fasthttp.RequestCtx) {
		ctx.Response.Header.Set("Location", "https://redirected.com/newpath")
		ctx.SetStatusCode(fasthttp.StatusMovedPermanently) // 301
	}

	// Start server
	serverCh := make(chan struct{})
	go func() {
		if err := fasthttp.Serve(ln, redirectHandler); err != nil {
			t.Errorf("server error: %v", err)
		}
		close(serverCh)
	}()

	// Create client options with custom dialer
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	// Create request pool
	pool := rawhttp.NewRequestWorkerPool(clientOpts, 10, GB403ErrorHandler.NewErrorHandler(32))

	// Create test payload
	jobs := []payload.PayloadJob{
		{
			FullURL:      "http://example.com/test",
			Method:       "GET",
			BypassModule: "test-redirect",
			Headers:      []payload.Header{},
			PayloadToken: "test-token",
		},
	}

	// Process request and get results channel
	resultsChan := pool.ProcessRequests(jobs)

	// Read result
	var result *rawhttp.RawHTTPResponseDetails
	select {
	case result = <-resultsChan:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for response")
	}

	// Verify results
	if result == nil {
		t.Fatal("no result received")
	}

	GB403Logger.PrintGreen("Result Status Code: %v\n", result.StatusCode)
	GB403Logger.PrintGreen("Result Redirect URL: %s\n", string(result.RedirectURL))
	GB403Logger.PrintGreen("Result Response Headers: %s\n", string(result.ResponseHeaders))

	// Check status code
	if result.StatusCode != fasthttp.StatusMovedPermanently {
		t.Errorf("unexpected status code: got %d, want %d",
			result.StatusCode, fasthttp.StatusMovedPermanently)
	}

	// Check redirect URL
	expectedLocation := "https://redirected.com/newpath"
	if string(result.RedirectURL) != expectedLocation {
		t.Errorf("unexpected location: got %q, want %q",
			string(result.RedirectURL), expectedLocation)
	}

	GB403Logger.Info().Msgf("Location: %s\n", string(result.RedirectURL))

	// Cleanup
	ln.Close()

	// Wait for server shutdown
	select {
	case <-serverCh:
	case <-time.After(time.Second):
		t.Fatal("server shutdown timeout")
	}
}

func TestClient302RedirectCaseInsensitive(t *testing.T) {
	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	server := &fasthttp.Server{
		DisableHeaderNamesNormalizing: true,
		Handler: func(ctx *fasthttp.RequestCtx) {
			// Use lowercase 'location' header
			ctx.Response.Header.DisableNormalizing()
			ctx.Response.Header.Set("location", "https://redirected.com/newpath")
			ctx.SetStatusCode(fasthttp.StatusFound) // 302
		},
	}

	// Start server
	go func() {
		if err := server.Serve(ln); err != nil {
			t.Errorf("server error: %v", err)
		}
	}()

	// Create client options with custom dialer
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	// Create request pool
	pool := rawhttp.NewRequestWorkerPool(clientOpts, 10, GB403ErrorHandler.NewErrorHandler(32))

	// Create test payload
	jobs := []payload.PayloadJob{
		{
			FullURL:      "http://example.com/test",
			Method:       "GET",
			BypassModule: "test-redirect",
			Headers:      []payload.Header{},
			PayloadToken: "test-token",
		},
	}

	// Process request and get results
	resultsChan := pool.ProcessRequests(jobs)

	// Read result
	var result *rawhttp.RawHTTPResponseDetails
	select {
	case result = <-resultsChan:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for response")
	}

	// Verify results
	if result == nil {
		t.Fatal("no result received")
	}

	GB403Logger.PrintGreen("Result Status Code: %v\n", result.StatusCode)
	GB403Logger.PrintGreen("Result Redirect URL: %s\n", string(result.RedirectURL))
	GB403Logger.PrintGreen("Result Response Headers: %s\n", string(result.ResponseHeaders))

	expectedLocation := "https://redirected.com/newpath"
	if string(result.RedirectURL) != expectedLocation {
		t.Errorf("unexpected location: got %q, want %q",
			string(result.RedirectURL), expectedLocation)
	}
}

func TestRequestDelay(t *testing.T) {
	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Track request timestamps
	var requestTimes []time.Time
	var mu sync.Mutex

	// Setup handler that records request times
	handler := func(ctx *fasthttp.RequestCtx) {
		mu.Lock()
		requestTimes = append(requestTimes, time.Now())
		mu.Unlock()
		ctx.SetStatusCode(fasthttp.StatusOK)
	}

	// Start server
	serverCh := make(chan struct{})
	go func() {
		if err := fasthttp.Serve(ln, handler); err != nil {
			t.Errorf("server error: %v", err)
		}
		close(serverCh)
	}()

	// Create client options with delay
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.RequestDelay = 3 * time.Second
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	// Create request pool
	pool := rawhttp.NewRequestWorkerPool(clientOpts, 1, GB403ErrorHandler.NewErrorHandler(32))

	// Create test payloads
	jobs := []payload.PayloadJob{
		{
			FullURL:      "http://example.com/test1",
			Method:       "GET",
			BypassModule: "test-delay",
			Headers:      []payload.Header{},
			PayloadToken: "test-token-1",
		},
		{
			FullURL:      "http://example.com/test2",
			Method:       "GET",
			BypassModule: "test-delay",
			Headers:      []payload.Header{},
			PayloadToken: "test-token-2",
		},
		{
			FullURL:      "http://example.com/test3",
			Method:       "GET",
			BypassModule: "test-delay",
			Headers:      []payload.Header{},
			PayloadToken: "test-token-3",
		},
	}

	// Process requests
	resultsChan := pool.ProcessRequests(jobs)

	// Collect results
	var results []*rawhttp.RawHTTPResponseDetails
	for result := range resultsChan {
		results = append(results, result)
	}

	// Verify results count
	if len(results) != len(jobs) {
		t.Errorf("expected %d results, got %d", len(jobs), len(results))
	}

	// Verify delays between requests
	mu.Lock()
	if len(requestTimes) < 2 {
		mu.Unlock()
		t.Fatal("not enough requests recorded")
	}

	// Check intervals
	for i := 1; i < len(requestTimes); i++ {
		interval := requestTimes[i].Sub(requestTimes[i-1])
		if interval < 2800*time.Millisecond || interval > 3200*time.Millisecond {
			t.Errorf("unexpected interval between requests %d and %d: got %v, want ~3s",
				i-1, i, interval)
		}
	}
	mu.Unlock()

	// Cleanup
	ln.Close()
	<-serverCh
}

// go.exe test -timeout 30s -run ^TestRequestDelayWithMultipleWorkers$ github.com/slicingmelon/go-bypass-403/tests/integration -v
// === RUN   TestRequestDelayWithMultipleWorkers
// --- PASS: TestRequestDelayWithMultipleWorkers (6.00s)
// PASS
// ok  	github.com/slicingmelon/go-bypass-403/tests/integration	7.525s
func TestRequestDelayWithMultipleWorkers(t *testing.T) {
	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Just track request timestamps
	var timestamps []time.Time
	var mu sync.Mutex

	// Simple handler that just records timestamps
	handler := func(ctx *fasthttp.RequestCtx) {
		mu.Lock()
		timestamps = append(timestamps, time.Now())
		mu.Unlock()
		ctx.SetStatusCode(fasthttp.StatusOK)
	}

	// Start server
	serverCh := make(chan struct{})
	go func() {
		if err := fasthttp.Serve(ln, handler); err != nil {
			t.Errorf("server error: %v", err)
		}
		close(serverCh)
	}()

	// Create client with 3s delay
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.RequestDelay = 3 * time.Second
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	// Create pool with 3 workers
	pool := rawhttp.NewRequestWorkerPool(clientOpts, 3, GB403ErrorHandler.NewErrorHandler(32))

	// Create 6 test jobs
	jobs := []payload.PayloadJob{
		{FullURL: "http://example.com/test1", Method: "GET"},
		{FullURL: "http://example.com/test2", Method: "GET"},
		{FullURL: "http://example.com/test3", Method: "GET"},
		{FullURL: "http://example.com/test4", Method: "GET"},
		{FullURL: "http://example.com/test5", Method: "GET"},
		{FullURL: "http://example.com/test6", Method: "GET"},
	}

	// Process requests and collect results
	start := time.Now()
	resultsChan := pool.ProcessRequests(jobs)
	var results []*rawhttp.RawHTTPResponseDetails
	for result := range resultsChan {
		results = append(results, result)
	}

	// Total time should be ~6s (2 requests per worker with 3s delay)
	totalTime := time.Since(start)
	if totalTime > 7*time.Second {
		t.Errorf("Requests took too long: %v", totalTime)
	}
	if totalTime < 5*time.Second {
		t.Errorf("Requests too fast, delay not working: %v", totalTime)
	}

	// Verify we got all results
	if len(results) != len(jobs) {
		t.Errorf("expected %d results, got %d", len(jobs), len(results))
	}

	// Cleanup
	ln.Close()
	<-serverCh
}
