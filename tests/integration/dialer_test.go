package tests

import (
	"bufio"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func TestDialerInMemory(t *testing.T) {
	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Setup test handler
	testHandler := func(ctx *fasthttp.RequestCtx) {
		ctx.Response.Header.Set("X-Test", "inmemory-dialer-test")
		ctx.SetStatusCode(fasthttp.StatusOK)
	}

	// Start server
	serverCh := make(chan struct{})
	go func() {
		if err := fasthttp.Serve(ln, testHandler); err != nil {
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
	pool := rawhttp.NewRequestWorkerPool(clientOpts, 1, GB403ErrorHandler.NewErrorHandler(32))

	// Create test payload
	jobs := []payload.PayloadJob{
		{
			FullURL:      "http://example.com/test",
			Method:       "GET",
			BypassModule: "test-dialer",
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

	if result.StatusCode != fasthttp.StatusOK {
		t.Errorf("unexpected status code: got %d, want %d",
			result.StatusCode, fasthttp.StatusOK)
	}

	// Cleanup
	ln.Close()
}

func TestDialerWithProxy(t *testing.T) {
	// Create a simple echo server
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	proxyRequestCount := &atomic.Int64{}

	// Simple handler that just counts requests and returns 200
	handler := func(ctx *fasthttp.RequestCtx) {
		proxyRequestCount.Add(1)
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBodyString("Proxied response")
	}

	// Start server
	go func() {
		if err := fasthttp.Serve(ln, handler); err != nil {
			t.Errorf("server error: %v", err)
		}
	}()

	// Create client options with proxy
	clientOpts := rawhttp.DefaultHTTPClientOptions()

	clientOpts.ProxyURL = "http://localhost:8089"
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	// Create request pool
	pool := rawhttp.NewRequestWorkerPool(clientOpts, 1, GB403ErrorHandler.NewErrorHandler(32))

	// Create test payload
	jobs := []payload.PayloadJob{
		{
			FullURL:      "http://example.com/test",
			Method:       "GET",
			BypassModule: "test-proxy",
			Headers:      []payload.Header{},
			PayloadToken: "test-proxy-token",
		},
	}

	// Small delay to ensure server is ready
	time.Sleep(100 * time.Millisecond)

	// Process request and get results
	resultsChan := pool.ProcessRequests(jobs)

	var result *rawhttp.RawHTTPResponseDetails
	select {
	case result = <-resultsChan:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for response")
	}

	if result == nil {
		t.Fatal("no result received")
	}

	GB403Logger.PrintGreen("Proxy requests count: %d\n", proxyRequestCount.Load())
	GB403Logger.PrintGreen("Response Status Code: %d\n", result.StatusCode)
	GB403Logger.PrintGreen("Response Headers: %s\n", string(result.ResponseHeaders))
}

func startProxyServer(t *testing.T, ports []string, counts []*atomic.Int64) (lns []net.Listener) {
	for i, port := range ports {
		ln, err := net.Listen("tcp", ":"+port)
		if err != nil {
			t.Fatal(err)
		}
		lns = append(lns, ln)
		i := i
		counter := counts[i]

		go func() {
			req := fasthttp.AcquireRequest()
			defer fasthttp.ReleaseRequest(req)

			for {
				conn, err := ln.Accept()
				if err != nil {
					if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
						t.Error(err)
					}
					break
				}

				err = req.Read(bufio.NewReader(conn))
				if err != nil {
					t.Error(err)
					conn.Close()
					continue
				}

				if string(req.Header.Method()) == "CONNECT" {
					counter.Add(1) // Use the counter reference
				}

				_, err = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				if err != nil {
					t.Error(err)
					conn.Close()
					continue
				}

				conn.Close()
				req.Reset()
			}
		}()
	}
	return
}
