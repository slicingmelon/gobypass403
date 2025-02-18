package tests

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func TestUnicodeBytes(t *testing.T) {
	// Create a buffer to simulate writing a raw HTTP request
	buf := bytes.NewBuffer(nil)

	// Unicode string in the request line
	unicodePath := "/path/こんにちは" // Japanese "Hello"

	// Write the request line with Unicode
	buf.WriteString("GET ")
	buf.WriteString(unicodePath)
	buf.WriteString(" HTTP/1.1\r\n")

	// Write a Host header
	buf.WriteString("Host: evil.com\r\n")

	// Write a custom header with Unicode
	unicodeHeader := "X-Test-Header: こんにちは\r\n"
	buf.WriteString(unicodeHeader)

	// End of headers
	buf.WriteString("\r\n")

	// Print the raw request bytes for inspection
	rawBytes := buf.Bytes()
	fmt.Printf("Raw request bytes (hex): %x\n", rawBytes)
	fmt.Printf("Raw request bytes (string): %s\n", rawBytes)

	// Verify the raw bytes contain the expected UTF-8 sequences
	expectedPathBytes := []byte(unicodePath)
	if !bytes.Contains(rawBytes, expectedPathBytes) {
		t.Errorf("Expected raw bytes to contain UTF-8 encoded path: %x", expectedPathBytes)
	}

	expectedHeaderBytes := []byte(unicodeHeader)
	if !bytes.Contains(rawBytes, expectedHeaderBytes) {
		t.Errorf("Expected raw bytes to contain UTF-8 encoded header: %x", expectedHeaderBytes)
	}
}

func TestRawHTTPClientBuildAndSendRequest(t *testing.T) {
	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Setup server handler
	serverHandler := func(ctx *fasthttp.RequestCtx) {
		t.Logf("Received request:")
		t.Logf("Request line: %s %s %s", ctx.Method(), ctx.RequestURI(), ctx.Request.Header.Protocol())
		t.Logf("Host header: %s", string(ctx.Request.Header.Peek("Host")))
		t.Logf("X-Test-Header: %s", string(ctx.Request.Header.Peek("X-Test-Header")))
		t.Logf("Full Headers:\n%s", ctx.Request.Header.String())

		// Verify the request line
		if string(ctx.RequestURI()) != "/path/こんにちは" {
			t.Errorf("Expected request line to be 'GET /path/こんにちは HTTP/1.1', but got '%s %s %s'",
				ctx.Method(), ctx.RequestURI(), ctx.Request.Header.Protocol())
		}

		// Simulate response
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBodyString("Request received")
	}

	// Start server
	serverCh := make(chan struct{})
	go func() {
		if err := fasthttp.Serve(ln, serverHandler); err != nil {
			t.Errorf("server error: %v", err)
		}
		close(serverCh)
	}()

	// Create rawhttp.HTTPClient with default options
	client := rawhttp.NewHTTPClient(rawhttp.DefaultHTTPClientOptions())

	// Create a PayloadJob with Unicode in the path and headers
	job := payload.PayloadJob{
		Method: "GET",
		Scheme: "http",
		Host:   "localhost:80",
		RawURI: "/path/こんにちは", // Unicode path
		Headers: []payload.Headers{
			{Header: "Host", Value: "evil.com"},       // Spoofed Host header
			{Header: "X-Test-Header", Value: "こんにちは"}, // Unicode header
		},
		PayloadToken: "debug-token-123",
	}

	// Create fasthttp.Request
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// Build the raw HTTP request
	err := rawhttp.BuildRawHTTPRequest(client, req, job)
	assert.NoError(t, err, "Failed to build raw HTTP request")

	// Log the request details
	t.Logf("Sending request to: http://localhost")
	t.Logf("Request line: %s %s %s", req.Header.Method(), req.URI().Path(), req.Header.Protocol())
	t.Logf("Using Host header: %s", string(req.Header.Peek("Host")))
	t.Logf("Request headers:\n%s", req.Header.String())

	// Send request using the in-memory listener
	_, err = client.DoRequest(req, resp, payload.PayloadJob{})
	assert.NoError(t, err, "Failed to send request")

	// Verify response
	assert.Equal(t, fasthttp.StatusOK, resp.StatusCode())
	assert.Equal(t, "Request received", string(resp.Body()))

	// Verify the Host header was set correctly
	assert.Equal(t, "evil.com", string(req.Header.Peek("Host")))
	assert.Equal(t, "こんにちは", string(req.Header.Peek("X-Test-Header")))
}

func TestRawHTTPClientBuildAndSendRequestDirectLocalhost(t *testing.T) {
	// Create rawhttp.HTTPClient with default options
	client := rawhttp.NewHTTPClient(rawhttp.DefaultHTTPClientOptions())

	opts := rawhttp.DefaultHTTPClientOptions()
	opts.Dialer = rawhttp.CreateDialFunc(opts)
	client.SetHTTPClientOptions(opts)

	// Create a PayloadJob with Unicode in the path and headers
	job := payload.PayloadJob{
		Method: "GET",
		Scheme: "http",
		Host:   "127.0.0.1",   // Target your test server here
		RawURI: "/path/こんにちは", // Unicode path
		Headers: []payload.Headers{
			{Header: "Host", Value: "evil.com"},       // Spoofed Host header
			{Header: "X-Test-Header", Value: "こんにちは"}, // Unicode header
		},
		PayloadToken: "debug-token-123",
	}

	// Create fasthttp.Request
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// Build the raw HTTP request
	err := rawhttp.BuildRawHTTPRequest(client, req, job)
	assert.NoError(t, err, "Failed to build raw HTTP request")

	// Log the request details
	t.Logf("Sending request to: %s", job.Host)
	t.Logf("Request line: %s %s %s", req.Header.Method(), req.URI().Path(), req.Header.Protocol())
	t.Logf("Using Host header: %s", string(req.Header.Peek("Host")))
	t.Logf("Request headers:\n%s", req.Header.String())

	// Send request to the real server
	_, err = client.DoRequest(req, resp, payload.PayloadJob{})
	assert.NoError(t, err, "Failed to send request")

	// Verify response
	assert.Equal(t, fasthttp.StatusOK, resp.StatusCode())
	assert.Equal(t, "Request received", string(resp.Body()))

	// Verify the Host header was set correctly
	assert.Equal(t, "evil.com", string(req.Header.Peek("Host")))
	assert.Equal(t, "こんにちは", string(req.Header.Peek("X-Test-Header")))
}
