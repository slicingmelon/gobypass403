package tests

import (
	"bytes"
	"net"
	"testing"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func TestResponseBodyStreamingWithConnectionClose(t *testing.T) {
	// Create an in-memory listener
	ln := fasthttputil.NewInmemoryListener()

	// Setup the server
	server := &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			// Set response with Connection: close
			ctx.SetStatusCode(fasthttp.StatusForbidden)
			ctx.Response.Header.Set("Connection", "close")
			ctx.Response.Header.Set("Content-Length", "12")
			ctx.Response.SetBodyString("Access Denied")
		},
	}

	// Start the server in a goroutine
	go func() {
		if err := server.Serve(ln); err != nil {
			t.Errorf("Server error: %v", err)
		}
	}()

	// Create the client with StreamResponseBody enabled
	client := &fasthttp.Client{
		StreamResponseBody: true,
		Dial: func(addr string) (net.Conn, error) {
			return ln.Dial()
		},
	}

	// Create request and response
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()

	// Set request URI
	req.SetRequestURI("http://example.com")

	// Perform the request
	if err := client.Do(req, resp); err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	// Verify status code
	if resp.StatusCode() != fasthttp.StatusForbidden {
		t.Errorf("Expected status code %d, got %d", fasthttp.StatusForbidden, resp.StatusCode())
	}

	// Verify connection close header
	if !resp.ConnectionClose() {
		t.Error("Expected Connection: close header")
	}

	// Read the response body
	stream := resp.BodyStream()
	if stream == nil {
		t.Fatal("Expected non-nil body stream")
	}

	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(stream)
	if err != nil {
		t.Fatalf("Error reading body stream: %v", err)
	}

	// Verify response body
	expectedBody := "Access Denied"
	if buf.String() != expectedBody {
		t.Errorf("Expected body %q, got %q", expectedBody, buf.String())
	}

	// Close the stream
	if err := resp.CloseBodyStream(); err != nil {
		t.Errorf("Error closing body stream: %v", err)
	}
}
