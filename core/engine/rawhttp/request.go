/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package rawhttp

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
	"sync"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/bytesutil"
	"github.com/valyala/fasthttp"
)

var (
	strUserAgentHeader = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
)

// Pre-defined byte slices for common strings to reduce allocations
var (
	bHost            = []byte("Host")
	bHostColon       = []byte("Host: ")
	bAccept          = []byte("Accept: */*\r\n")
	bColonSpace      = []byte(": ")
	bCRLF            = []byte("\r\n")
	bConnectionKeep  = []byte("Connection: keep-alive\r\n")
	bConnectionClose = []byte("Connection: close\r\n")
	bContentLength   = []byte("Content-Length: ")
	bXGB403Token     = []byte("X-GB403-Token: ")
)

var (
	requestBufferPool = bytesutil.ByteBufferPool{}

	rawRequestBuffReaderPool = sync.Pool{
		New: func() any {
			return bufio.NewReader(nil)
		},
	}
)

/*
Crucial information

Client determines the server to be requested in the following order:

  - from RequestURI if it contains full url with scheme and host;
  - from Host header otherwise.

The function doesn't follow redirects. Use Get* for following redirects.
Response is ignored if resp is nil.

The detination/target URL is built based on req.URI, aka where the request will be sent to.

Use req.URI().SetScheme("https") to set the scheme to https
Use req.URI().SetHost("example.com") to set the target host -> this is where the request will be sent to
Use req.SetRequestURI("/path") to set the path (e.g., / or /ssdaf).

For spoofed/custom Host header!
Set req.UseHostHeader = true to ensure the custom Host header is used instead of the URI host (fasthttp will extract it from the URI)
Use req.Header.Set("Host", "evil.com") to set the spoofed Host header

To set true raw request line, e.g. GET @evil.com HTTP/1.1, do not set req.SetRequestURI() and write the raw request line manually.

For this to work, everything must be set in order, Raw Request line, headers, then appply settings,
then set req.UseHostHeader = true and then req.URI().SetScheme() and req.URI().SetHost()
*/
func BuildRawHTTPRequest(httpclient *HTTPClient, req *fasthttp.Request, bypassPayload payload.BypassPayload) error {
	// Build the raw HTTP request
	bb, _ := BuildRawRequest(httpclient, bypassPayload)
	defer requestBufferPool.Put(bb)

	// Wrap the raw request into a FastHTTP request
	return WrapRawFastHTTPRequest(req, bb, bypassPayload)
}

// BuildRawRequest builds a raw HTTP request from the bypass payload and returns the byte buffer
// and a flag indicating if the connection should be closed
func BuildRawRequest(httpclient *HTTPClient, bypassPayload payload.BypassPayload) (*bytesutil.ByteBuffer, bool) {
	// Get client options once
	clientOpts := httpclient.GetHTTPClientOptions()

	// Define shouldCloseConn based on general factors
	shouldCloseConn := clientOpts.DisableKeepAlive ||
		clientOpts.ProxyURL != "" ||
		bypassPayload.BypassModule == "headers_scheme" ||
		bypassPayload.BypassModule == "headers_ip" ||
		bypassPayload.BypassModule == "headers_port" ||
		bypassPayload.BypassModule == "headers_url" ||
		bypassPayload.BypassModule == "headers_host"

	// Get ByteBuffer from pool
	bb := requestBufferPool.Get()

	// Build request line directly into byte buffer
	bb.B = append(bb.B, bypassPayload.Method...)
	bb.B = append(bb.B, ' ')
	bb.B = append(bb.B, bypassPayload.RawURI...)
	bb.B = append(bb.B, " HTTP/1.1\r\n"...)

	// Track which headers we've added to avoid duplicates
	addedHeaders := make(map[string]bool, len(clientOpts.ParsedHeaders)+len(bypassPayload.Headers)+5)
	hasHostHeader := false
	hasContentLength := false
	hasConnectionHeader := false

	// PRIORITY 1: Add CLI custom headers first (highest priority)
	for _, h := range clientOpts.ParsedHeaders {
		headerLower := strings.ToLower(h.Name)

		// Set special header flags
		if headerLower == "host" {
			hasHostHeader = true
			shouldCloseConn = true
		} else if headerLower == "content-length" {
			hasContentLength = true
		} else if headerLower == "connection" {
			hasConnectionHeader = true
			shouldCloseConn = true
		}

		// Add header with original case preserved
		bb.B = append(bb.B, h.Name...)
		bb.B = append(bb.B, bColonSpace...)
		bb.B = append(bb.B, h.Value...)
		bb.B = append(bb.B, bCRLF...)

		// Mark as added
		addedHeaders[headerLower] = true
	}

	// PRIORITY 2: Add payload headers (skip if already added by CLI)
	for _, h := range bypassPayload.Headers {
		headerLower := strings.ToLower(h.Header)

		// Skip if CLI header already added this
		if addedHeaders[headerLower] {
			continue
		}

		// Set special header flags
		if headerLower == "host" {
			hasHostHeader = true
			shouldCloseConn = true
		} else if headerLower == "content-length" {
			hasContentLength = true
		} else if headerLower == "connection" {
			hasConnectionHeader = true
			shouldCloseConn = true
		}

		// Add header with original case preserved
		bb.B = append(bb.B, h.Header...)
		bb.B = append(bb.B, bColonSpace...)
		bb.B = append(bb.B, h.Value...)
		bb.B = append(bb.B, bCRLF...)

		// Mark as added
		addedHeaders[headerLower] = true
	}

	// PRIORITY 3: Add default Host header if not provided
	if !hasHostHeader {
		bb.B = append(bb.B, bHostColon...)
		bb.B = append(bb.B, bypassPayload.Host...)
		bb.B = append(bb.B, bCRLF...)
	}

	// PRIORITY 4: Add standard headers (User-Agent, Accept) if not overridden
	if !addedHeaders["user-agent"] {
		bb.B = append(bb.B, strUserAgentHeader...)
		bb.B = append(bb.B, bCRLF...)
	}
	if !addedHeaders["accept"] {
		bb.B = append(bb.B, bAccept...)
	}

	// Add Debug token if debug mode is enabled and not overridden
	if GB403Logger.IsDebugEnabled() && !addedHeaders["x-gb403-token"] {
		bb.B = append(bb.B, bXGB403Token...)
		bb.B = append(bb.B, bypassPayload.PayloadToken...)
		bb.B = append(bb.B, bCRLF...)
	}

	// Add Content-Length header if body exists and wasn't explicitly set
	if len(bypassPayload.Body) > 0 && !hasContentLength {
		bb.B = append(bb.B, bContentLength...)
		bb.B = append(bb.B, strconv.Itoa(len(bypassPayload.Body))...)
		bb.B = append(bb.B, bCRLF...)
	}

	// Add Connection header LAST if not explicitly set
	if !hasConnectionHeader {
		if shouldCloseConn {
			bb.B = append(bb.B, bConnectionClose...)
		} else {
			bb.B = append(bb.B, bConnectionKeep...)
		}
	}

	// End of headers marker
	bb.B = append(bb.B, bCRLF...)

	// Add body if present
	if len(bypassPayload.Body) > 0 {
		bb.B = append(bb.B, bypassPayload.Body...)
	}

	return bb, shouldCloseConn
}

// WrapRawFastHTTPRequest wraps a raw HTTP request into a FastHTTP request
func WrapRawFastHTTPRequest(req *fasthttp.Request, rawRequest *bytesutil.ByteBuffer, bypassPayload payload.BypassPayload) error {
	// Get bufio.Reader from pool and reset it with our ByteBuffer reader
	br := rawRequestBuffReaderPool.Get().(*bufio.Reader)
	br.Reset(bytes.NewReader(rawRequest.B))
	defer rawRequestBuffReaderPool.Put(br)

	// Apply all flags at once
	applyReqFlags(req)

	// Let FastHTTP parse the entire request (headers + body)
	if err := req.ReadLimitBody(br, 0); err != nil {
		return err
	}

	// Set URI components after successful parsing
	req.URI().SetScheme(bypassPayload.Scheme)
	req.URI().SetHost(bypassPayload.Host)

	GB403Logger.Debug().Msgf("== Wrapped raw request ==:\n%s", string(rawRequest.B))
	return nil
}

func applyReqFlags(req *fasthttp.Request) {
	req.URI().DisablePathNormalizing = true
	req.Header.DisableNormalizing()
	req.Header.SetNoDefaultContentType(true)
	req.UseHostHeader = true
}

func ReqCopyToWithSettings(src *fasthttp.Request, dst *fasthttp.Request) *fasthttp.Request {
	// Copy basic request data
	src.CopyTo(dst)

	// Log initial state after copy
	//GB403Logger.Debug().Msgf("After CopyTo - scheme=%s host=%s",
	//	src.URI().Scheme(), src.URI().Host()) // Use bytes directly in logging

	applyReqFlags(dst)

	// Store original values as []byte
	originalScheme := src.URI().Scheme()
	originalHost := src.URI().Host()

	//GB403Logger.Debug().Msgf("Original values - scheme=%s host=%s",
	//	originalScheme, originalHost) // Use bytes directly in logging

	// Use byte variants to avoid allocations
	dst.URI().SetSchemeBytes(originalScheme)
	dst.URI().SetHostBytes(originalHost)

	// Check if Host header exists using case-insensitive lookup
	if len(PeekRequestHeaderKeyCaseInsensitive(dst, bHost)) == 0 {
		//GB403Logger.Debug().Msgf("No Host header found, setting from URI.Host: %s", originalHost)
		dst.Header.SetHostBytes(originalHost)
	}

	// GB403Logger.Debug().Msgf("After SetScheme/SetHost - scheme=%s host=%s header_host=%s",
	// 	dst.URI().Scheme(), dst.URI().Host(),
	// 	PeekRequestHeaderKeyCaseInsensitive(dst, hostKey))

	return dst
}

func PeekRequestHeaderKeyCaseInsensitive(h *fasthttp.Request, key []byte) []byte {
	var result []byte
	h.Header.VisitAll(func(k, v []byte) {
		if result == nil && bytes.EqualFold(k, key) {
			result = v
		}
	})
	return result
}
