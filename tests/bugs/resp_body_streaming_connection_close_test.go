package tests

import (
	"bytes"
	"net"
	"strconv"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
	"github.com/slicingmelon/gobypass403/core/engine/rawhttp"
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

func TestResponseBodyStreamingWithConnectionClose2(t *testing.T) {
	// Create an in-memory listener
	ln := fasthttputil.NewInmemoryListener()

	// Setup the server
	server := &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			// Set response with Connection: close
			ctx.SetStatusCode(fasthttp.StatusForbidden)
			ctx.Response.Header.Set("Connection", "close")

			// Create a large response body (17KB)
			largeBody := make([]byte, 17*1024)
			for i := range largeBody {
				largeBody[i] = 'A'
			}
			ctx.Response.Header.Set("Content-Length", strconv.Itoa(len(largeBody)))
			ctx.Response.SetBodyRaw(largeBody)
		},
	}

	// Start the server in a goroutine
	go func() {
		if err := server.Serve(ln); err != nil {
			t.Errorf("Server error: %v", err)
		}
	}()

	// Create the rawhttp client with StreamResponseBody enabled
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.StreamResponseBody = true
	// clientOpts.Dialer = func(addr string) (net.Conn, error) {
	// 	return ln.Dial()
	//}

	client := rawhttp.NewHTTPClient(clientOpts)

	// Create request and response
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()

	// Create a full bypass payload for testing
	bypassPayload := payload.BypassPayload{
		Method:       "GET",
		Scheme:       "https",
		Host:         "localhost",
		RawURI:       "/test-path",
		BypassModule: "test-module",
		PayloadToken: "test-token",
		Headers: []payload.Headers{
			{
				Header: "User-Agent",
				Value:  "Test-Agent",
			},
			{
				Header: "Accept",
				Value:  "text/html",
			},
		},
	}

	// Build the raw HTTP request
	if err := rawhttp.BuildRawHTTPRequest(client, req, bypassPayload); err != nil {
		t.Fatalf("Failed to build raw HTTP request: %v", err)
	}

	// Perform the request
	_, err := client.DoRequest(req, resp, bypassPayload)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	// Process the response
	result := rawhttp.ProcessHTTPResponse(client, resp, bypassPayload)

	// Verify status code
	if result.StatusCode != fasthttp.StatusOK {
		t.Errorf("Expected status code %d, got %d", fasthttp.StatusOK, result.StatusCode)
	}

	// Verify connection close header
	if !resp.ConnectionClose() {
		t.Error("Expected Connection: close header")
	}

	// Verify response body
	expectedBody := "Access Denied"
	if len(result.ResponsePreview) > 0 && string(result.ResponsePreview) != expectedBody {
		t.Errorf("Expected body %q, got %q", expectedBody, string(result.ResponsePreview))
	}
}
