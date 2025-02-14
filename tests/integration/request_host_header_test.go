package tests

import (
	"net"
	"testing"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func TestHostHeaderInjection(t *testing.T) {
	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Setup server handler
	serverHandler := func(ctx *fasthttp.RequestCtx) {
		host := string(ctx.Request.Header.Peek("Host"))

		// Log received request details for debugging
		t.Logf("Received request:")
		t.Logf("Host header: %s", host)
		t.Logf("RequestURI: %s", ctx.RequestURI())
		t.Logf("Full Headers:\n%s", ctx.Request.Header.String())

		// Simulate host header based redirection vulnerability
		if host == "evil.com:1337" {
			ctx.Response.Header.Set("Location", "https://evil.com/pwned")
			ctx.SetStatusCode(fasthttp.StatusFound) // 302
			return
		}

		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBodyString("Normal response")
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
	client := rawhttp.NewHTTPClient(rawhttp.DefaultHTTPClientOptions())
	client.GetHTTPClientOptions().Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	// Test cases
	testCases := []struct {
		name         string
		targetURL    string
		hostHeader   string
		expectedCode int
	}{
		{
			name:         "Normal request",
			targetURL:    "https://example.com/path",
			hostHeader:   "example.com",
			expectedCode: 200,
		},
		{
			name:         "Host header injection attempt",
			targetURL:    "https://example.com/path",
			hostHeader:   "evil.com:1337",
			expectedCode: 302,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create request
			req := fasthttp.AcquireRequest()
			defer fasthttp.ReleaseRequest(req)
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseResponse(resp)

			// Setup payload job
			job := payload.PayloadJob{
				FullURL: tc.targetURL,
				Method:  "GET",
				Headers: []payload.Headers{
					{
						Header: "Host",
						Value:  tc.hostHeader,
					},
				},
			}

			// Build and send request
			err := rawhttp.BuildHTTPRequest(client, req, job)
			//req.UseHostHeader = true
			assert.NoError(t, err)

			_, err = client.DoRequest(req, resp)
			assert.NoError(t, err)

			// Verify response
			assert.Equal(t, tc.expectedCode, resp.StatusCode())
		})
	}
}

func TestHostHeaderInjection2(t *testing.T) {
	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Setup server handler
	serverHandler := func(ctx *fasthttp.RequestCtx) {
		host := string(ctx.Request.Header.Peek("Host"))

		// Log received request details for debugging
		t.Logf("Received request:")
		t.Logf("Host header: %s", host)
		t.Logf("RequestURI: %s", ctx.RequestURI())
		t.Logf("Full Headers:\n%s", ctx.Request.Header.String())

		// Simulate pornhub.com behavior:
		if host != "pornhub.com" {
			ctx.Response.Reset() // Clear any default headers
			ctx.Response.Header.Set("Server", "openresty")
			ctx.Response.Header.Set("Content-Type", "text/html")
			ctx.Response.Header.Set("Location", "https://www.pornhub.com/")
			ctx.SetStatusCode(fasthttp.StatusMovedPermanently) // 301
			ctx.SetBodyString("<html>\n<head><title>301 Moved Permanently</title></head>\n<body>\n<center><h1>301 Moved Permanently</h1></center>\n<hr><center>openresty</center>\n</body>\n</html>")
			return
		}

		// Normal response for matching host
		ctx.Response.Reset() // Clear any default headers
		ctx.Response.Header.Set("Location", "https://www.pornhub.com/")
		ctx.Response.Header.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		ctx.SetStatusCode(fasthttp.StatusMovedPermanently)
		ctx.SetBodyString("")
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
	client := rawhttp.NewHTTPClient(rawhttp.DefaultHTTPClientOptions())
	//opts := client.GetHTTPClientOptions()
	// opts.Dialer = func(addr string) (net.Conn, error) {
	// 	return ln.Dial()
	// }

	// Test cases remain the same
	testCases := []struct {
		name             string
		targetURL        string
		hostHeader       string
		expectedCode     int
		expectedLocation string
		expectedServer   string
	}{
		{
			name:             "Normal request with matching host",
			targetURL:        "https://brazzerstoys.com/",
			hostHeader:       "www.google.com",
			expectedCode:     301,
			expectedLocation: "https://www.pornhub.com/",
			expectedServer:   "",
		},
		{
			name:             "Request with different host header",
			targetURL:        "https://brazzerstoys.com/",
			hostHeader:       "google.com",
			expectedCode:     301,
			expectedLocation: "https://brazzerstoys.com/",
			expectedServer:   "openresty",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create request
			req := fasthttp.AcquireRequest()
			defer fasthttp.ReleaseRequest(req)
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseResponse(resp)

			// Setup payload job
			job := payload.PayloadJob{
				FullURL: tc.targetURL,
				Method:  "GET",
				Headers: []payload.Headers{
					{
						Header: "Host",
						Value:  tc.hostHeader,
					},
				},
			}

			// Build and send request
			// err := rawhttp.BuildHTTPRequest(client, req, job)
			// assert.NoError(t, err)

			req.SetRequestURI(job.FullURL)

			req.UseHostHeader = true
			req.URI().SetScheme("https")
			// Log the actual request being sent
			t.Logf("Sending request with headers:\n%s", req.Header.String())

			_, err := client.DoRequest(req, resp)
			assert.NoError(t, err)

			// Log the response received
			t.Logf("Received response:\nStatus: %d\nHeaders:\n%s\nBody: %s\n",
				resp.StatusCode(),
				resp.Header.String(),
				resp.Body())

			// Verify response
			assert.Equal(t, tc.expectedCode, resp.StatusCode())
			assert.Equal(t, tc.expectedLocation, string(resp.Header.Peek("Location")))

			if tc.expectedServer != "" {
				assert.Equal(t, tc.expectedServer, string(resp.Header.Peek("Server")))
			}

			// Verify the Host header was set correctly
			assert.Equal(t, tc.hostHeader, string(req.Header.Peek("Host")))
		})
	}
}

func TestManualHostHeaderInjection(t *testing.T) {
	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Setup server handler
	serverHandler := func(ctx *fasthttp.RequestCtx) {
		host := string(ctx.Request.Header.Peek("Host"))

		t.Logf("Received request:")
		t.Logf("Host header: %s", host)
		t.Logf("RequestURI: %s", ctx.RequestURI())
		t.Logf("Full Headers:\n%s", ctx.Request.Header.String())

		// Simulate different behavior based on host header
		switch host {
		case "evil.com":
			ctx.SetStatusCode(fasthttp.StatusFound)
			ctx.Response.Header.Set("Location", "https://evil.com/pwned")
		case "admin.internal":
			ctx.SetStatusCode(fasthttp.StatusOK)
			ctx.SetBodyString("Admin panel accessed")
		default:
			ctx.SetStatusCode(fasthttp.StatusForbidden)
		}
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
	client := rawhttp.NewHTTPClient(rawhttp.DefaultHTTPClientOptions())
	client.GetHTTPClientOptions().Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	// Test cases
	testCases := []struct {
		name         string
		targetHost   string
		path         string
		hostHeader   string
		expectedCode int
		expectedBody string
	}{
		{
			name:         "Normal request",
			targetHost:   "example.com",
			path:         "/",
			hostHeader:   "example.com",
			expectedCode: 403,
		},
		{
			name:         "Host header injection - evil.com",
			targetHost:   "example.com",
			path:         "/",
			hostHeader:   "evil.com",
			expectedCode: 302,
		},
		{
			name:         "Host header injection - admin.internal",
			targetHost:   "example.com",
			path:         "/admin",
			hostHeader:   "admin.internal",
			expectedCode: 200,
			expectedBody: "Admin panel accessed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create request
			req := fasthttp.AcquireRequest()
			defer fasthttp.ReleaseRequest(req)
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseResponse(resp)

			// Manually set up the request
			req.SetRequestURI(tc.path)
			req.URI().SetScheme("https")
			req.URI().SetHost(tc.targetHost)

			// Enable custom host header
			req.UseHostHeader = true
			req.Header.SetHost(tc.hostHeader)

			// Log the request details
			t.Logf("Sending request to: https://%s%s", tc.targetHost, tc.path)
			t.Logf("Using Host header: %s", tc.hostHeader)
			t.Logf("Request headers:\n%s", req.Header.String())

			// Send request
			_, err := client.DoRequest(req, resp)
			assert.NoError(t, err)

			// Verify response
			assert.Equal(t, tc.expectedCode, resp.StatusCode())
			if tc.expectedBody != "" {
				assert.Equal(t, tc.expectedBody, string(resp.Body()))
			}

			// Verify the Host header was set correctly
			assert.Equal(t, tc.hostHeader, string(req.Header.Peek("Host")))
		})
	}
}

func TestManualHostHeaderInjection2(t *testing.T) {
	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Setup server handler
	serverHandler := func(ctx *fasthttp.RequestCtx) {
		host := string(ctx.Request.Header.Peek("Host"))

		t.Logf("Received request:")
		t.Logf("Host header: %s", host)
		t.Logf("RequestURI: %s", ctx.RequestURI())
		t.Logf("Full Headers:\n%s", ctx.Request.Header.String())

		// Simulate different behavior based on host header
		switch host {
		case "evil.com":
			ctx.SetStatusCode(fasthttp.StatusFound)
			ctx.Response.Header.Set("Location", "https://evil.com/pwned")
		case "admin.internal":
			ctx.SetStatusCode(fasthttp.StatusOK)
			ctx.SetBodyString("Admin panel accessed")
		default:
			ctx.SetStatusCode(fasthttp.StatusForbidden)
		}
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
	}

	// Test cases
	testCases := []struct {
		name         string
		targetHost   string
		path         string
		hostHeader   string
		expectedCode int
		expectedBody string
	}{
		{
			name:         "Normal request",
			targetHost:   "example.com",
			path:         "/",
			hostHeader:   "example.com",
			expectedCode: 403,
		},
		{
			name:         "Host header injection - evil.com",
			targetHost:   "example.com",
			path:         "/",
			hostHeader:   "evil.com",
			expectedCode: 302,
		},
		{
			name:         "Host header injection - admin.internal",
			targetHost:   "example.com",
			path:         "/admin",
			hostHeader:   "admin.internal",
			expectedCode: 200,
			expectedBody: "Admin panel accessed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create request
			req := fasthttp.AcquireRequest()
			defer fasthttp.ReleaseRequest(req)
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseResponse(resp)

			// Manually set up the request
			req.SetRequestURI(tc.path)
			req.URI().SetScheme("http") // Use http for in-memory listener
			req.URI().SetHost(tc.targetHost)

			// Enable custom host header
			req.UseHostHeader = true
			req.Header.SetHost(tc.hostHeader)

			// Log the request details
			t.Logf("Sending request to: http://%s%s", tc.targetHost, tc.path)
			t.Logf("Using Host header: %s", tc.hostHeader)
			t.Logf("Request headers:\n%s", req.Header.String())

			// Send request
			err := client.Do(req, resp)
			assert.NoError(t, err)

			// Verify response
			assert.Equal(t, tc.expectedCode, resp.StatusCode())
			if tc.expectedBody != "" {
				assert.Equal(t, tc.expectedBody, string(resp.Body()))
			}

			// Verify the Host header was set correctly
			assert.Equal(t, tc.hostHeader, string(req.Header.Peek("Host")))
		})
	}
}
