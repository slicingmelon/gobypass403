package rawhttp

import (
	"bytes"
	"net"
	"sync"
	"testing"

	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func TestRequestBuilderViaEchoServer(t *testing.T) {
	t.Parallel()

	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Store raw request for verification
	var rawRequest []byte
	var mu sync.Mutex

	// Setup test server that echoes back raw request
	s := &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			mu.Lock()
			defer mu.Unlock()

			// Get the raw request bytes
			rawRequest = make([]byte, len(ctx.Request.Header.RawHeaders()))
			copy(rawRequest, ctx.Request.Header.RawHeaders())

			// Echo back exactly what we received
			ctx.Write(rawRequest)

			logger.LogYellow("\n=== Raw Request Received ===\n%s\n==================",
				string(rawRequest))
		},
	}

	go func() {
		if err := s.Serve(ln); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	}()

	c := &fasthttp.Client{
		Dial: func(addr string) (net.Conn, error) {
			return ln.Dial()
		},
	}

	t.Run("test request", func(t *testing.T) {
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseRequest(req)
		defer fasthttp.ReleaseResponse(resp)

		req.SetRequestURI("http://example.com/test")
		req.Header.SetMethod("GET")

		logger.LogGreen("\n=== Sending Request ===\n%s\n==================",
			string(req.Header.RawHeaders()))

		if err := c.Do(req, resp); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		mu.Lock()
		if !bytes.Equal(rawRequest, req.Header.RawHeaders()) {
			t.Errorf("\nExpected raw request:\n%q\nGot:\n%q",
				string(req.Header.RawHeaders()),
				string(rawRequest))
		}
		mu.Unlock()
	})
}
