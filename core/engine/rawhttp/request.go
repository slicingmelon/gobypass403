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
	// Add byte slices for case-insensitive header comparisons
	bHostLower          = []byte("host")
	bContentLengthLower = []byte("content-length")
	bConnectionLower    = []byte("connection")
	bUserAgentLower     = []byte("user-agent")
	bAcceptLower        = []byte("accept")
	bXGB403TokenLower   = []byte("x-gb403-token")
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

	// Wrap the raw request into a FastHTTP request for other modules
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

	// Debug logging for HAProxy bypasses to track body handling
	if bypassPayload.BypassModule == "haproxy_bypasses" {
		GB403Logger.Debug().Msgf("== HAProxy Bypass Debug ==")
		GB403Logger.Debug().Msgf("Body length: %d", len(bypassPayload.Body))
		GB403Logger.Debug().Msgf("Body content: %q", string(bypassPayload.Body))
		GB403Logger.Debug().Msgf("Headers count: %d", len(bypassPayload.Headers))
		for i, h := range bypassPayload.Headers {
			GB403Logger.Debug().Msgf("Header[%d]: %s = %s", i, h.Header, h.Value)
		}
	}

	// Build request line directly into byte buffer
	bb.B = append(bb.B, bypassPayload.Method...)
	bb.B = append(bb.B, ' ')
	bb.B = append(bb.B, bypassPayload.RawURI...)
	bb.B = append(bb.B, " HTTP/1.1\r\n"...)

	// Use HeaderOverrides map instead of creating new map
	// This avoids allocation since it's pre-computed during client initialization
	hasHostHeader := false
	hasContentLength := false
	hasConnectionHeader := false

	// Check if CLI headers override special headers
	if clientOpts.HeaderOverrides != nil {
		hasHostHeader = clientOpts.HeaderOverrides["host"]
		hasContentLength = clientOpts.HeaderOverrides["content-length"]
		hasConnectionHeader = clientOpts.HeaderOverrides["connection"]

		// Update shouldCloseConn based on CLI overrides
		if hasHostHeader || hasConnectionHeader {
			shouldCloseConn = true
		}
	}

	// PRIORITY 1: Add CLI custom headers first (highest priority)
	for _, h := range clientOpts.ParsedHeaders {
		// Use fast case-insensitive comparison with pre-computed byte slices
		if isHeaderNameEqual(h.Name, bHostLower) {
			hasHostHeader = true
			shouldCloseConn = true
		} else if isHeaderNameEqual(h.Name, bContentLengthLower) {
			hasContentLength = true
		} else if isHeaderNameEqual(h.Name, bConnectionLower) {
			hasConnectionHeader = true
			shouldCloseConn = true
		}

		// Add header with original case preserved
		bb.B = append(bb.B, h.Name...)
		bb.B = append(bb.B, bColonSpace...)
		bb.B = append(bb.B, h.Value...)
		bb.B = append(bb.B, bCRLF...)
	}

	// PRIORITY 2: Add payload headers (skip if already added by CLI)
	// For certain modules, defer Content-Length headers to be added just before Connection
	var deferredContentLengthHeaders []payload.Headers
	shouldDeferContentLength := bypassPayload.BypassModule == "haproxy_bypasses"

	for _, h := range bypassPayload.Headers {
		// Use HeaderOverrides map to check if CLI already added this header
		// Use fast case-insensitive comparison to avoid strings.ToLower() allocation
		if clientOpts.HeaderOverrides != nil {
			// Check against each CLI header using case-insensitive comparison
			skipHeader := false
			for _, cliHeader := range clientOpts.ParsedHeaders {
				if bytes.EqualFold([]byte(h.Header), []byte(cliHeader.Name)) {
					skipHeader = true
					break
				}
			}
			if skipHeader {
				continue
			}
		}

		// Use fast case-insensitive comparison for special headers
		isHost := isHeaderNameEqual(h.Header, bHostLower)
		isContentLength := isHeaderNameEqual(h.Header, bContentLengthLower)
		isConnection := isHeaderNameEqual(h.Header, bConnectionLower)

		// For modules that need special Content-Length ordering, defer real Content-Length headers
		if shouldDeferContentLength && isContentLength && h.Header == "Content-Length" {
			deferredContentLengthHeaders = append(deferredContentLengthHeaders, h)
			hasContentLength = true // Mark as having Content-Length to prevent auto-generation
			continue
		}

		// Set special header flags
		if isHost {
			hasHostHeader = true
			shouldCloseConn = true
		} else if isContentLength {
			hasContentLength = true
		} else if isConnection {
			hasConnectionHeader = true
			shouldCloseConn = true
		}

		// Add header with original case preserved
		bb.B = append(bb.B, h.Header...)
		bb.B = append(bb.B, bColonSpace...)
		bb.B = append(bb.B, h.Value...)
		bb.B = append(bb.B, bCRLF...)
	}

	// PRIORITY 3: Add default Host header if not provided
	if !hasHostHeader {
		bb.B = append(bb.B, bHostColon...)
		bb.B = append(bb.B, bypassPayload.Host...)
		bb.B = append(bb.B, bCRLF...)
	}

	// PRIORITY 4: Add standard headers if not overridden by CLI
	if clientOpts.HeaderOverrides == nil || !clientOpts.HeaderOverrides["user-agent"] {
		bb.B = append(bb.B, strUserAgentHeader...)
		bb.B = append(bb.B, bCRLF...)
	}
	if clientOpts.HeaderOverrides == nil || !clientOpts.HeaderOverrides["accept"] {
		bb.B = append(bb.B, bAccept...)
	}

	// Add Debug token if debug mode is enabled and not overridden
	if GB403Logger.IsDebugEnabled() &&
		(clientOpts.HeaderOverrides == nil || !clientOpts.HeaderOverrides["x-gb403-token"]) {
		bb.B = append(bb.B, bXGB403Token...)
		bb.B = append(bb.B, bypassPayload.PayloadToken...)
		bb.B = append(bb.B, bCRLF...)
	}

	// Add Content-Length header if body exists and wasn't explicitly set
	// SKIP auto Content-Length if we have deferred headers (HAProxy exploit)
	if len(bypassPayload.Body) > 0 && !hasContentLength && len(deferredContentLengthHeaders) == 0 {
		bb.B = append(bb.B, bContentLength...)
		bb.B = append(bb.B, strconv.Itoa(len(bypassPayload.Body))...)
		bb.B = append(bb.B, bCRLF...)
	}

	// Add Connection header if not explicitly set
	if !hasConnectionHeader {
		if shouldCloseConn {
			bb.B = append(bb.B, bConnectionClose...)
		} else {
			bb.B = append(bb.B, bConnectionKeep...)
		}
	}

	// Add deferred Content-Length headers LAST before end of headers (critical for HAProxy exploit)
	for _, h := range deferredContentLengthHeaders {
		bb.B = append(bb.B, h.Header...)
		bb.B = append(bb.B, bColonSpace...)
		bb.B = append(bb.B, h.Value...)
		bb.B = append(bb.B, bCRLF...)
	}

	// End of headers marker
	bb.B = append(bb.B, bCRLF...)

	// Additional debug for HAProxy body handling
	// if bypassPayload.BypassModule == "haproxy_bypasses" {
	GB403Logger.Debug().Msgf("== Before body addition ==")
	GB403Logger.Debug().Msgf("Body length: %d", len(bypassPayload.Body))
	GB403Logger.Debug().Msgf("Body is empty: %t", len(bypassPayload.Body) == 0)
	GB403Logger.Debug().Msgf("Body content: %q", string(bypassPayload.Body))
	GB403Logger.Debug().Msgf("Request so far (%d bytes):\n%s", len(bb.B), string(bb.B))
	// }

	// Add body if present
	if len(bypassPayload.Body) > 0 {
		GB403Logger.Debug().Msgf("== Adding body to request (%d bytes) ==: %q", len(bypassPayload.Body), string(bypassPayload.Body))
		bb.B = append(bb.B, bypassPayload.Body...)

	} else {
		GB403Logger.Debug().Msgf("== No body to add (bypassPayload.Body is empty) ==")
	}

	return bb, shouldCloseConn
}

// WrapRawFastHTTPRequest wraps a raw HTTP request into a FastHTTP request
func WrapRawFastHTTPRequest(req *fasthttp.Request, rawRequest *bytesutil.ByteBuffer, bypassPayload payload.BypassPayload) error {
	// Get bufio.Reader from pool and reset it with our ByteBuffer reader
	br := rawRequestBuffReaderPool.Get().(*bufio.Reader)
	br.Reset(bytes.NewReader(rawRequest.B))
	defer rawRequestBuffReaderPool.Put(br)

	// Apply all flags BEFORE parsing to ensure raw mode
	applyReqFlags(req)

	// Let FastHTTP parse the entire request (headers + body)
	if err := req.ReadLimitBody(br, 0); err != nil {
		return err
	}

	if len(bypassPayload.Body) > 0 {
		req.SetBodyRaw([]byte(bypassPayload.Body))
	}

	// Debug the parsed request
	GB403Logger.Debug().Msgf("== FastHTTP Parsed Request ==")
	GB403Logger.Debug().Msgf("Method: %s", req.Header.Method())
	GB403Logger.Debug().Msgf("RequestURI: %s", req.Header.RequestURI())
	GB403Logger.Debug().Msgf("ContentLength from header: %d", req.Header.ContentLength())
	GB403Logger.Debug().Msgf("Body length: %d", len(req.Body()))
	GB403Logger.Debug().Msgf("Body content: %q", string(req.Body()))

	// Log all headers
	GB403Logger.Debug().Msgf("== All Headers ==")
	req.Header.VisitAll(func(key, value []byte) {
		GB403Logger.Debug().Msgf("Header: %s = %s", string(key), string(value))
	})

	// Apply flags again after parsing to ensure they stick
	//applyReqFlags(req)

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
	req.Header.DisableSpecialHeader()
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

// isHeaderNameEqual performs case-insensitive header name comparison using bytes.EqualFold
// This avoids the allocation from strings.ToLower()
func isHeaderNameEqual(headerName string, target []byte) bool {
	//return bytes.EqualFold(bytesutil.ToUnsafeBytes(headerName), target)
	return bytes.EqualFold([]byte(headerName), target)
}
