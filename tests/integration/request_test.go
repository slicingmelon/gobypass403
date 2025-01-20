package tests

import (
	"net"
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
	clientOpts := rawhttp.DefaultOptionsSameHost()
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	// Create request pool
	pool := rawhttp.NewRequestPool(clientOpts, &rawhttp.ScannerCliOpts{
		ResponseBodyPreviewSize: 100,
		ModuleName:              "test-redirect",
		MaxWorkers:              10,
	}, GB403ErrorHandler.NewErrorHandler(32))

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

	// Setup server with custom config
	server := &fasthttp.Server{
		DisableHeaderNamesNormalizing: true, // Add this
		Handler: func(ctx *fasthttp.RequestCtx) {
			// Use lowercase 'location' header
			ctx.Response.Header.DisableNormalizing() // Add this
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
	clientOpts := rawhttp.DefaultOptionsSameHost()
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	// Create request pool
	pool := rawhttp.NewRequestPool(clientOpts, &rawhttp.ScannerCliOpts{
		ResponseBodyPreviewSize: 100,
		ModuleName:              "test-redirect",
		MaxWorkers:              10,
	}, GB403ErrorHandler.NewErrorHandler(32))

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
