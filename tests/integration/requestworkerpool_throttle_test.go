package tests

import (
	"net"
	"testing"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func TestRequestWorkerPoolThrottle(t *testing.T) {
	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	requestCount := 0
	serverDone := make(chan bool)

	server := &fasthttp.Server{
		DisableHeaderNamesNormalizing: true,
		Handler: func(ctx *fasthttp.RequestCtx) {
			requestCount++
			ctx.Response.Header.DisableNormalizing()

			// Add artificial delay to better observe throttling
			switch requestCount {
			case 1:
				t.Logf("Server: Request %d - Returning 429", requestCount)
				ctx.SetStatusCode(fasthttp.StatusTooManyRequests)
			case 2:
				t.Logf("Server: Request %d - Returning 429", requestCount)
				time.Sleep(100 * time.Millisecond) // Add delay
				ctx.SetStatusCode(fasthttp.StatusTooManyRequests)
			default:
				t.Logf("Server: Request %d - Returning 200", requestCount)
				ctx.SetStatusCode(fasthttp.StatusOK)
			}
		},
	}

	// Start server with proper shutdown
	go func() {
		if err := server.Serve(ln); err != nil {
			t.Errorf("server error: %v", err)
		}
		serverDone <- true
	}()

	// Create client options with custom dialer
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	// Create request pool with smaller worker count
	pool := rawhttp.NewRequestWorkerPool(clientOpts, 2) // Reduced workers
	defer pool.Close()

	// Log initial pool stats
	t.Logf("Initial pool stats - Active workers: %d, Submitted tasks: %d",
		pool.GetReqWPActiveWorkers(),
		pool.GetReqWPSubmittedTasks())

	// Create test jobs
	jobs := []payload.PayloadJob{
		{
			Scheme:       "http",
			Host:         "example.com",
			RawURI:       "/test1",
			BypassModule: "test-throttle",
		},
		{
			Scheme:       "http",
			Host:         "example.com",
			RawURI:       "/test2",
			BypassModule: "test-throttle",
		},
		{
			Scheme:       "http",
			Host:         "example.com",
			RawURI:       "/test3",
			BypassModule: "test-throttle",
		},
	}

	start := time.Now()
	resultsChan := pool.ProcessRequests(jobs)
	var results []*rawhttp.RawHTTPResponseDetails

	// Monitor pool stats during processing
	statsDone := make(chan bool)
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				t.Logf("Pool stats - Active Workers: %d, Submitted: %d, Waiting: %d, Completed: %d",
					pool.GetReqWPActiveWorkers(),
					pool.GetReqWPSubmittedTasks(),
					pool.GetReqWPWaitingTasks(),
					pool.GetReqWPCompletedTasks())
			case <-statsDone:
				return
			}
		}
	}()

	// Collect results with timeout
	timeout := time.After(5 * time.Second)
	done := make(chan bool)

	go func() {
		for result := range resultsChan {
			if result != nil {
				t.Logf("Received result - Status: %d, Time since start: %v",
					result.StatusCode,
					time.Since(start))
				results = append(results, result)
			}
			if len(results) == len(jobs) {
				done <- true
				return
			}
		}
		done <- false
	}()

	// Wait for completion or timeout
	select {
	case success := <-done:
		if !success {
			t.Fatal("Not all results received")
		}
	case <-timeout:
		t.Fatal("Test timed out")
	}

	close(statsDone)

	// Log final stats
	t.Logf("Final pool stats - Active Workers: %d, Submitted: %d, Completed: %d",
		pool.GetReqWPActiveWorkers(),
		pool.GetReqWPSubmittedTasks(),
		pool.GetReqWPCompletedTasks())

	// Verify results
	if len(results) != len(jobs) {
		t.Fatalf("Expected %d results, got %d", len(jobs), len(results))
	}

	// Verify status codes and timing
	for i, result := range results {
		t.Logf("Result %d - Status: %d", i+1, result.StatusCode)
	}

	assert.Equal(t, fasthttp.StatusTooManyRequests, results[0].StatusCode, "First request should be 429")
	assert.Equal(t, fasthttp.StatusTooManyRequests, results[1].StatusCode, "Second request should be 429")
	assert.Equal(t, fasthttp.StatusOK, results[2].StatusCode, "Third request should be 200")

	// Clean up
	ln.Close()
	<-serverDone
}
