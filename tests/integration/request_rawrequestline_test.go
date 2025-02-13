package tests

import (
	"bufio"
	"bytes"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func TestManualRawRequestWithCustomRequestLineLocalhost(t *testing.T) {
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

	//Create client with mock listener
	// client := &fasthttp.Client{
	// 	Dial: func(addr string) (net.Conn, error) {
	// 		return ln.Dial()
	// 	},
	// }
	client := &fasthttp.Client{}

	// Create request
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// Manually build the raw request
	req.SetRequestURI("")
	req.URI().SetScheme("http")
	req.URI().SetHost("localhost")
	req.URI().DisablePathNormalizing = true
	// Use custom Host header
	req.UseHostHeader = true
	req.Header.SetHost("localhost")
	// Write the raw request line and headers
	req.Header.SetMethod("GET")
	req.Header.Set("X-Test-Header", "123")

	// Log the request details
	t.Logf("Sending request to: http://example.com")
	t.Logf("Request line: GET @test.com HTTP/1.1")
	t.Logf("Using Host header: evil.com")
	t.Logf("Request headers:\n%s", req.Header.String())

	// Send request
	err := client.Do(req, resp)
	assert.NoError(t, err)

	// Verify response
	assert.Equal(t, fasthttp.StatusOK, resp.StatusCode())
	assert.Equal(t, "Request received", string(resp.Body()))

	// Verify the Host header was set correctly
	assert.Equal(t, "evil.com", string(req.Header.Peek("Host")))
	assert.Equal(t, "123", string(req.Header.Peek("X-Test-Header")))
}

func TestManualRawRequestWithCustomRequestLineLocalhost2(t *testing.T) {
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
		if string(ctx.RequestURI()) != "@test.com" {
			t.Errorf("Expected request line to be 'GET @test.com HTTP/1.1', but got '%s %s %s'",
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

	// Create client with mock listener
	client := &fasthttp.Client{}

	// 	Dial: func(addr string) (net.Conn, error) {
	// 		return ln.Dial()
	// 	},
	// }

	// Create request
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// Manually build the raw request
	//req.SetRequestURI("") // Leave URI empty
	req.URI().SetScheme("http")
	req.URI().SetHost("localhost")
	req.URI().DisablePathNormalizing = true

	// Use custom Host header
	req.UseHostHeader = true
	req.Header.Set("Host", "evil.com")

	// Manually write the raw request line
	req.Header.SetMethod("GET")
	req.Header.SetRequestURIBytes([]byte("@test.com")) // Set the custom request line

	// Add custom headers
	req.Header.Set("X-Test-Header", "123")

	// Log the request details
	t.Logf("Sending request to: http://localhost")
	t.Logf("Request line: GET @test.com HTTP/1.1")
	t.Logf("Using Host header: evil.com")
	t.Logf("Request headers:\n%s", req.Header.String())

	// Send request
	err := client.Do(req, resp)
	assert.NoError(t, err)

	// Verify response
	assert.Equal(t, fasthttp.StatusOK, resp.StatusCode())
	assert.Equal(t, "Request received", string(resp.Body()))

	// Verify the Host header was set correctly
	assert.Equal(t, "evil.com", string(req.Header.Peek("Host")))
	assert.Equal(t, "123", string(req.Header.Peek("X-Test-Header")))
}

func TestManualRawRequestWithRawRequestLineViaWriteString(t *testing.T) {
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
		if string(ctx.RequestURI()) != "@test.com" {
			t.Errorf("Expected request line to be 'GET @test.com HTTP/1.1', but got '%s %s %s'",
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

	// Create client with mock listener
	// client := &fasthttp.Client{
	// 	Dial: func(addr string) (net.Conn, error) {
	// 		return ln.Dial()
	// 	},
	// }

	client := &fasthttp.Client{DisablePathNormalizing: true}

	// Create request
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// Manually build the raw request using WriteString
	buf := bytes.NewBuffer(nil)

	// Write the request line
	buf.WriteString("GET @test/こんにちは HTTP/1.1\r\n")

	// Write the Host header
	buf.WriteString("Host: evil.com\r\n")

	// Write custom headers
	buf.WriteString("X-Test-Header: 123\r\n")

	// End of headers
	buf.WriteString("\r\n")

	// Parse the raw request into fasthttp.Request
	br := bufio.NewReader(buf)
	if err := req.Read(br); err != nil {
		t.Fatalf("Failed to parse raw request: %v", err)
	}

	// Use custom Host header
	req.UseHostHeader = true

	// Set the target host in the URI
	req.URI().SetScheme("http")
	req.URI().SetHost("localhost")
	req.URI().DisablePathNormalizing = true

	// Log the request details
	t.Logf("Sending request to: http://localhost")
	t.Logf("Request line: GET @test.com HTTP/1.1")
	t.Logf("Using Host header: evil.com")
	t.Logf("Request headers:\n%s", req.Header.String())

	// Send request
	err := client.Do(req, resp)
	assert.NoError(t, err)

	// Verify response
	assert.Equal(t, fasthttp.StatusOK, resp.StatusCode())
	assert.Equal(t, "Request received", string(resp.Body()))

	// Verify the Host header was set correctly
	assert.Equal(t, "evil.com", string(req.Header.Peek("Host")))
	assert.Equal(t, "123", string(req.Header.Peek("X-Test-Header")))
}

func TestManualRawRequestWithRawRequestLineViaDirectDial(t *testing.T) {
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
		if string(ctx.RequestURI()) != "@test.com" {
			t.Errorf("Expected request line to be 'GET @test.com HTTP/1.1', but got '%s %s %s'",
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

	// Create client with mock listener
	// client := &fasthttp.Client{
	// 	Dial: func(addr string) (net.Conn, error) {
	// 		return ln.Dial()
	// 	},
	// }

	// Manually build the raw request
	rawRequest := "GET @test.com HTTP/1.1\r\n" +
		"Host: evil.com\r\n" +
		"X-Test-Header: 123\r\n" +
		"\r\n"

	// Send the raw request
	conn, err := ln.Dial()
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte(rawRequest))
	if err != nil {
		t.Fatalf("Failed to write request: %v", err)
	}

	// Read the response
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	if err := resp.Read(bufio.NewReader(conn)); err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Verify response
	assert.Equal(t, fasthttp.StatusOK, resp.StatusCode())
	assert.Equal(t, "Request received", string(resp.Body()))
}

func TestManualRawRequestWithCustomRequestLineViaURIUPDATE(t *testing.T) {
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
		if string(ctx.RequestURI()) != "@test.com" {
			t.Errorf("Expected request line to be 'GET @test.com HTTP/1.1', but got '%s %s %s'",
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

	// Create client with mock listener
	client := &fasthttp.Client{
		Dial: func(addr string) (net.Conn, error) {
			return ln.Dial()
		},
		DisablePathNormalizing: true,
	}

	// Create request
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// Set the initial request URI to an empty string
	req.SetRequestURI("")

	// Update the URI object to include the custom request line
	u := req.URI()
	u.SetScheme("http")
	u.SetHost("localhost")
	u.DisablePathNormalizing = true
	u.SetPath("@test.com") // Set the custom request line

	// Use custom Host header
	req.UseHostHeader = true
	req.Header.Set("Host", "evil.com")

	// Add custom headers
	req.Header.Set("X-Test-Header", "123")

	// Log the request details
	t.Logf("Sending request to: http://localhost")
	t.Logf("Request line: GET @test.com HTTP/1.1")
	t.Logf("Using Host header: evil.com")
	t.Logf("Request headers:\n%s", req.Header.String())

	// Send request
	err := client.Do(req, resp)
	assert.NoError(t, err)

	// Verify response
	assert.Equal(t, fasthttp.StatusOK, resp.StatusCode())
	assert.Equal(t, "Request received", string(resp.Body()))

	// Verify the Host header was set correctly
	assert.Equal(t, "evil.com", string(req.Header.Peek("Host")))
	assert.Equal(t, "123", string(req.Header.Peek("X-Test-Header")))
}
