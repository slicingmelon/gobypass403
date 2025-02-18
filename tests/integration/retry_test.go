package tests

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func TestRetryOnEOF(t *testing.T) {
	GB403Logger.DefaultLogger.EnableDebug()

	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Track connection attempts
	connectionAttempts := atomic.Int32{}

	// Start server
	go func() {
		err := fasthttp.Serve(ln, func(ctx *fasthttp.RequestCtx) {
			attempts := connectionAttempts.Add(1)
			t.Logf("Server handling attempt %d", attempts)

			if attempts <= 2 {
				// Send completely malformed response
				_, err := ctx.Write([]byte("   200 OK\r\nContent-Length: 5\r\n\r\nhello"))
				if err != nil {
					t.Errorf("Failed to write response: %v", err)
				}
				t.Logf("Server sending malformed response for attempt %d", attempts)
			} else {
				// Send proper response
				ctx.Response.SetStatusCode(200)
				ctx.WriteString("success")
				t.Logf("Server sending proper response for attempt %d", attempts)
			}
		})
		if err != nil {
			t.Errorf("Unexpected server error: %v", err)
		}
	}()

	// Create client options
	opts := rawhttp.DefaultHTTPClientOptions()
	opts.MaxRetries = 4
	opts.Timeout = 20 * time.Second
	opts.RetryDelay = 100 * time.Millisecond
	opts.DisableKeepAlive = false

	// Use broken connection for first two attempts
	opts.Dialer = func(addr string) (net.Conn, error) {
		conn, err := ln.Dial()
		if err != nil {
			return nil, err
		}

		currentAttempt := connectionAttempts.Load()
		t.Logf("Dialer creating connection for attempt %d", currentAttempt)

		if currentAttempt <= 2 {
			return &brokenConn{
				Conn:       conn,
				breakAfter: 10, // Break after just 10 bytes
				t:          t,
			}, nil
		}
		return conn, nil
	}

	// Create client with error handler that logs errors
	client := rawhttp.NewHTTPClient(opts)

	// Prepare request
	req := client.AcquireRequest()
	resp := client.AcquireResponse()
	defer client.ReleaseRequest(req)
	defer client.ReleaseResponse(resp)

	req.SetRequestURI("http://test.local/test")

	// Execute request and capture each error
	_, err := client.DoRequest(req, resp, payload.PayloadJob{})
	t.Logf("DoRequest returned error: %v", err)

	// Log for debugging
	t.Logf("Final error: %v", err)
	t.Logf("Retry attempts: %d", client.GetPerReqRetryAttempts())
	t.Logf("Connection attempts: %d", connectionAttempts.Load())

	// Assertions
	assert.NoError(t, err, "Expected successful request after retries")
	assert.Equal(t, "success", string(resp.Body()), "Expected success response")
	assert.Equal(t, int32(3), connectionAttempts.Load(), "Expected exactly 3 connection attempts")
	assert.Equal(t, int32(2), client.GetPerReqRetryAttempts(), "Expected 2 retry attempts")

	client.Close()
}

// brokenConn simulates a connection that breaks after N bytes
type brokenConn struct {
	net.Conn
	bytesRead  int
	breakAfter int
	t          *testing.T
}

func (c *brokenConn) Read(b []byte) (n int, err error) {
	if c.bytesRead >= c.breakAfter {
		c.t.Logf("brokenConn: forcing immediate EOF after %d bytes", c.bytesRead)
		return 0, io.EOF
	}

	// Only read up to breakAfter bytes
	if c.bytesRead+len(b) > c.breakAfter {
		n = c.breakAfter - c.bytesRead
		copy(b[:n], make([]byte, n))
		c.bytesRead += n
		c.t.Logf("brokenConn: partial read %d bytes (total: %d), returning EOF", n, c.bytesRead)
		return n, io.EOF
	}

	n = len(b)
	copy(b, make([]byte, n))
	c.bytesRead += n
	c.t.Logf("brokenConn: read %d bytes (total: %d)", n, c.bytesRead)
	return n, nil
}

func TestRetryWithPayloads(t *testing.T) {
	// Create base client options
	opts := rawhttp.DefaultHTTPClientOptions()
	opts.MaxRetries = 2
	opts.Timeout = 20 * time.Second
	opts.RetryDelay = 100 * time.Millisecond
	//opts.DisableKeepAlive = true
	opts.MaxConnsPerHost = 100

	client := rawhttp.NewHTTPClient(opts)
	defer client.Close()

	baseURL := "http://cms.uviu.com/test"
	payloads := []string{
		"/.;",
		"/.;/",
		"/.;//",
		"/..",
		"/..;/",
		"/..;/;/",
		"/..;/;/..;/",
		"/..;/..;/",
		"/..;/../",
		"/..;//",
		"/..;//..;/",
		"/..;//../",
		"/..;%2f",
		"/..;%2f..;%2f",
		"/..;%2f..;%2f..;%2f",
		"/../",
		"/../;/",
		"/../;/../",
		"/../.;/../",
		"/../..;/",
		"/../../",
		"/../../../",
		"/../../..//",
		"/../..//",
		"/../..//../",
		"/.././../",
		"/..//",
		"/..//..;/",
		"/..//../",
		"/..//../../",
		"/..%2f",
		"/..%2f..%2f",
		"/..%2f..%2f..%2f",
		"/./",
		"/.//",
		"/.%00",
		"/.%00/",
		"/.randomstring",
		"/../",
		"/../;/",
		"/../;/../",
		"/../.;/../",
		"/../..;/",
		"/../../",
		"/../../../",
		"/../../..//",
		"/../..//",
		"/../..//../",
		"/.././../",
		"/..//",
		"/..//..;/",
		"/..//../",
		"/..//../../",
		"/..%2f",
		"/..%2f..%2f",
		"/..%2f..%2f..%2f",
		"/./",
		"/.//",
		"/.%00",
		"/.%00/",
		"/.randomstring",
		"/../",
		"/../;/",
		"/../;/../",
		"/../.;/../",
		"/../..;/",
		"/../../",
		"/../../../",
		"/../../..//",
		"/../..//",
		"/../..//../",
		"/.././../",
		"/..//",
		"/..//..;/",
		"/..//../",
		"/..//../../",
		"/..%2f",
		"/..%2f..%2f",
		"/..%2f..%2f..%2f",
		"/./",
		"/.//",
		"/.%00",
		"/.%00/",
		"/.randomstring",
	}

	results := make(chan struct {
		payload string
		retries int32
		err     error
	}, len(payloads))

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5) // Limit concurrent requests

	// Launch goroutine to process payloads
	for i, _payload := range payloads {
		wg.Add(1)
		go func(p string, idx int) {
			defer wg.Done()

			// Acquire semaphore
			t.Logf("Goroutine %d: Waiting for semaphore", idx)
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			t.Logf("Goroutine %d: Got semaphore, processing payload: %s", idx, p)

			// Each goroutine gets its own request/response objects
			req := client.AcquireRequest()
			resp := client.AcquireResponse()
			defer client.ReleaseRequest(req)
			defer client.ReleaseResponse(resp)

			fullURL := baseURL + p
			req.SetRequestURI(fullURL)
			t.Logf("Goroutine %d: Sending request to %s", idx, fullURL)

			_, err := client.DoRequest(req, resp, payload.PayloadJob{})
			t.Logf("Goroutine %d: Got response with error: %v", idx, err)

			results <- struct {
				payload string
				retries int32
				err     error
			}{
				payload: p,
				retries: client.GetPerReqRetryAttempts(),
				err:     err,
			}
			t.Logf("Goroutine %d: Sent result to channel", idx)
		}(_payload, i)
	}

	t.Log("All goroutines launched, waiting for completion")

	// Start a goroutine to close results channel when all work is done
	go func() {
		t.Log("Waiting for all goroutines to complete")
		wg.Wait()
		t.Log("All goroutines completed, closing results channel")
		close(results)
	}()

	// Collect results with a timeout
	timeout := time.After(25 * time.Second)
	resultCount := 0

	t.Log("Starting to collect results")
	for resultCount < len(payloads) {
		select {
		case result, ok := <-results:
			if !ok {
				t.Log("Results channel closed")
				return
			}
			t.Logf("Got result %d/%d", resultCount+1, len(payloads))
			t.Logf("Payload: %s", result.payload)
			t.Logf("  Retries: %d", result.retries)
			t.Logf("  Error: %v", result.err)
			t.Logf("---")
			resultCount++
		case <-timeout:
			t.Fatal("Test timed out waiting for results")
			return
		}
	}

	t.Log("All results collected")
}

var requestCount int32

func TestRetryWithLargeResponse(t *testing.T) {
	requestCount = 0

	// Create large response body (larger than what we tell in Content-Length)
	largeBody := make([]byte, 2000) // Much larger than our max
	for i := range largeBody {
		largeBody[i] = 'A'
	}

	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Start fasthttp server
	go func() {
		err := fasthttp.Serve(ln, func(ctx *fasthttp.RequestCtx) {
			count := atomic.AddInt32(&requestCount, 1)
			t.Logf("Server: handling request attempt %d", count)

			// Tell client we're sending less data than we actually will
			ctx.Response.Header.SetContentLength(1500) // fake content length

			// Write more data than declared
			ctx.Write(largeBody) // This will trigger ErrBodyTooLarge

			t.Logf("Server: sent large response for attempt %d", count)
		})
		if err != nil {
			t.Errorf("Server error: %v", err)
		}
	}()

	// Create client options with small max response size
	opts := rawhttp.DefaultHTTPClientOptions()
	opts.MaxRetries = 2
	opts.Timeout = 500 * time.Millisecond
	opts.RetryDelay = 100 * time.Millisecond
	opts.MaxResponseBodySize = 1030
	opts.MaxConnsPerHost = 100
	opts.ReadBufferSize = 1030
	opts.WriteBufferSize = 1030
	opts.StreamResponseBody = false

	// Set up the dialer to use our in-memory listener
	opts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	client := rawhttp.NewHTTPClient(opts)
	defer client.Close()

	// Test with a single request
	req := client.AcquireRequest()
	resp := client.AcquireResponse()
	defer client.ReleaseRequest(req)
	defer client.ReleaseResponse(resp)

	req.SetRequestURI("http://localhost/test") // The actual URL doesn't matter with our custom dialer
	t.Log("Sending request...")

	_, err := client.DoRequest(req, resp, payload.PayloadJob{})
	t.Logf("Request completed with error: %v", err)

	// Verify retry count
	retries := client.GetPerReqRetryAttempts()
	t.Logf("Got %d retries", retries)

	if retries != 2 {
		t.Errorf("Expected 2 retries, got %d", retries)
	}

	if !errors.Is(err, fasthttp.ErrBodyTooLarge) {
		t.Errorf("Expected ErrBodyTooLarge, got: %v", err)
	}
}

func TestRetryWithConcurrentRequests(t *testing.T) {
	const (
		concurrentRequests = 500
		requestDuration    = 5 * time.Second
	)

	requestCount := atomic.Int32{}
	retryCount := atomic.Int32{}
	errorCount := atomic.Int32{}

	// Create server
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	go func() {
		err := fasthttp.Serve(ln, func(ctx *fasthttp.RequestCtx) {
			requestCount.Add(1)
			ctx.Response.Header.SetContentLength(2000)
			ctx.Write(make([]byte, 2000)) // Trigger ErrBodyTooLarge
		})
		if err != nil {
			t.Errorf("Server error: %v", err)
		}
	}()

	// Create client
	opts := rawhttp.DefaultHTTPClientOptions()
	opts.MaxRetries = 2
	opts.Timeout = 500 * time.Millisecond
	opts.RetryDelay = 20 * time.Millisecond // Shorter delay for stress test
	opts.MaxResponseBodySize = 1030
	opts.MaxConnsPerHost = 100
	opts.ReadBufferSize = 1030
	opts.WriteBufferSize = 1030
	opts.StreamResponseBody = false
	opts.MaxConnsPerHost = 1000 // Allow many concurrent connections
	opts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	client := rawhttp.NewHTTPClient(opts)
	defer client.Close()

	// Start concurrent requests
	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < concurrentRequests; i++ {
		wg.Add(1)
		go func(num int) {
			defer wg.Done()

			req := client.AcquireRequest()
			resp := client.AcquireResponse()
			defer client.ReleaseRequest(req)
			defer client.ReleaseResponse(resp)

			req.SetRequestURI("http://localhost/test")
			_, err := client.DoRequest(req, resp, payload.PayloadJob{})

			if err != nil {
				errorCount.Add(1)
				if errors.Is(err, fasthttp.ErrBodyTooLarge) {
					retryCount.Add(1)
				}
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(start)

	t.Logf("Completed %d requests in %v", concurrentRequests, duration)
	t.Logf("Total requests to server: %d", requestCount.Load())
	t.Logf("Requests that triggered retry: %d", retryCount.Load())
	t.Logf("Total errors: %d", errorCount.Load())

	// Verify we got expected retry behavior
	if retryCount.Load() != concurrentRequests {
		t.Errorf("Expected all requests to retry, got %d/%d", retryCount.Load(), concurrentRequests)
	}
}

func TestRetryWhitespaceFirstLine(t *testing.T) {
	GB403Logger.DefaultLogger.EnableDebug()

	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Track connection attempts
	connectionAttempts := atomic.Int32{}

	// Start server that sends malformed response
	go func() {
		err := fasthttp.Serve(ln, func(ctx *fasthttp.RequestCtx) {
			attempts := connectionAttempts.Add(1)
			t.Logf("Server handling attempt %d", attempts)

			if attempts == 1 {
				// First attempt: send malformed response
				_, err := ctx.Write([]byte("TRaILeR:,\n\n"))
				if err != nil {
					t.Errorf("Failed to write response: %v", err)
				}
				t.Logf("Server sending malformed response")
			} else {
				// Subsequent attempts: send proper response
				ctx.Response.SetStatusCode(200)
				ctx.WriteString("success")
				t.Logf("Server sending proper response")
			}
		})
		if err != nil {
			t.Errorf("Unexpected server error: %v", err)
		}
	}()

	// Create client options
	opts := rawhttp.DefaultHTTPClientOptions()
	opts.MaxRetries = 4
	opts.Timeout = 2 * time.Second
	opts.RetryDelay = 100 * time.Millisecond

	// Set up the dialer to use our in-memory listener
	opts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	client := rawhttp.NewHTTPClient(opts)
	defer client.Close()

	// Prepare request
	req := client.AcquireRequest()
	resp := client.AcquireResponse()
	defer client.ReleaseRequest(req)
	defer client.ReleaseResponse(resp)

	req.SetRequestURI("http://localhost/test")

	// Execute request
	_, err := client.DoRequest(req, resp, payload.PayloadJob{})
	t.Logf("DoRequest returned error: %v", err)

	// Log for debugging
	t.Logf("Final error: %v", err)
	t.Logf("Retry attempts: %d", client.GetPerReqRetryAttempts())
	t.Logf("Connection attempts: %d", connectionAttempts.Load())

	// Assertions
	assert.NoError(t, err, "Expected successful request after retries")
	assert.Equal(t, "success", string(resp.Body()), "Expected success response")
	assert.Equal(t, int32(2), connectionAttempts.Load(), "Expected exactly 2 connection attempts")
	assert.Equal(t, int32(1), client.GetPerReqRetryAttempts(), "Expected 1 retry attempt")

	GB403ErrorHandler.GetErrorHandler().PrintErrorStats()
}
