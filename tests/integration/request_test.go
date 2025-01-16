package tests

import (
	"net"
	"testing"
	"time"

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

	// Setup client with in-memory dialer
	client := &fasthttp.Client{
		NoDefaultUserAgentHeader: true,
		DisablePathNormalizing:   true,
		Dial: func(addr string) (net.Conn, error) {
			return ln.Dial()
		},
	}

	// Prepare request
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.SetRequestURI("http://example.com/test")
	req.Header.SetMethod(fasthttp.MethodGet)

	// Prepare response
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// Send request
	err := client.Do(req, resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify status code
	if resp.StatusCode() != fasthttp.StatusMovedPermanently {
		t.Errorf("unexpected status code: got %d, want %d",
			resp.StatusCode(), fasthttp.StatusMovedPermanently)
	}

	// Check Location header
	location := resp.Header.Peek("Location")
	expectedLocation := "https://redirected.com/newpath"
	if string(location) != expectedLocation {
		t.Errorf("unexpected location: got %q, want %q",
			string(location), expectedLocation)
	}
	GB403Logger.Info().Msgf("Location: %s\n", string(location))

	// Cleanup
	ln.Close()

	// Wait for server shutdown
	select {
	case <-serverCh:
	case <-time.After(time.Second):
		t.Fatal("server shutdown timeout")
	}
}
