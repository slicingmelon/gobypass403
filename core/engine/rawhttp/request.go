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

	// Pool for header maps to reduce allocations
	headerMapPool = sync.Pool{
		New: func() any {
			return make(map[string]string)
		},
	}

	// Pool for string slices to reduce allocations during header name capitalization
	wordSlicePool = sync.Pool{
		New: func() any {
			return make([]string, 0, 8) // Most headers have fewer than 8 words
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

	// Track headers we've seen and will add
	hasHostHeader := false
	hasContentLength := false
	hasConnectionHeader := false

	// Get map from pool and clear it (in case it was previously used)
	clientCustomHeadersMap := headerMapPool.Get().(map[string]string)
	for k := range clientCustomHeadersMap {
		delete(clientCustomHeadersMap, k)
	}
	// Defer returning map to pool
	defer headerMapPool.Put(clientCustomHeadersMap)

	// Process client's custom headers if any
	if len(clientOpts.CustomHTTPHeaders) > 0 {
		for _, header := range clientOpts.CustomHTTPHeaders {
			colonIdx := strings.Index(header, ":")
			if colonIdx != -1 {
				headerName := strings.TrimSpace(header[:colonIdx])
				headerValue := strings.TrimSpace(header[colonIdx+1:])
				clientCustomHeadersMap[strings.ToLower(headerName)] = headerValue

				if strings.EqualFold(headerName, "Host") {
					hasHostHeader = true
					shouldCloseConn = true
				} else if strings.EqualFold(headerName, "Content-Length") {
					hasContentLength = true
				} else if strings.EqualFold(headerName, "Connection") {
					hasConnectionHeader = true
					shouldCloseConn = true
				}
			}
		}
	}

	// Add payload-specific headers first (giving them priority)
	for _, h := range bypassPayload.Headers {
		// Check if this header is going to be overridden by a client custom header
		_, willBeOverridden := clientCustomHeadersMap[strings.ToLower(h.Header)]

		// Skip if will be overridden, unless it's a critical header that modifies behavior
		if willBeOverridden &&
			!strings.EqualFold(h.Header, "Host") &&
			!strings.EqualFold(h.Header, "Content-Length") &&
			!strings.EqualFold(h.Header, "Connection") {
			continue
		}

		// Set flags for special headers
		if strings.EqualFold(h.Header, "Host") {
			hasHostHeader = true
			shouldCloseConn = true
			// Remove from custom headers map to avoid duplicate
			delete(clientCustomHeadersMap, "host")
		}
		if strings.EqualFold(h.Header, "Content-Length") {
			hasContentLength = true
			delete(clientCustomHeadersMap, "content-length")
		}
		if strings.EqualFold(h.Header, "Connection") {
			hasConnectionHeader = true
			shouldCloseConn = true
			delete(clientCustomHeadersMap, "connection")
		}

		// Append the header from the payload directly
		bb.B = append(bb.B, h.Header...)
		bb.B = append(bb.B, bColonSpace...)
		bb.B = append(bb.B, h.Value...)
		bb.B = append(bb.B, bCRLF...)
	}

	// Now add any client custom headers that weren't in the payload
	for headerNameLower, headerValue := range clientCustomHeadersMap {
		// We've already set the flags for special headers when building the map
		// Use original casing for the header name, not lowercase version

		// Get a string slice from the pool for words
		words := wordSlicePool.Get().([]string)
		words = words[:0] // Reset slice without allocating

		// Split by dash and store in our pooled slice
		for _, word := range strings.Split(headerNameLower, "-") {
			words = append(words, word)
		}

		// Build properly capitalized header name directly into byte buffer
		for i, word := range words {
			if i > 0 {
				bb.B = append(bb.B, '-')
			}

			if len(word) > 0 {
				// Capitalize first letter, keep rest as is
				bb.B = append(bb.B, byte(strings.ToUpper(word[:1])[0]))
				if len(word) > 1 {
					bb.B = append(bb.B, word[1:]...)
				}
			}
		}

		// Return the word slice to pool
		wordSlicePool.Put(words)

		// Add separator and value
		bb.B = append(bb.B, bColonSpace...)
		bb.B = append(bb.B, headerValue...)
		bb.B = append(bb.B, bCRLF...)
	}

	// Add Host header if not explicitly provided in the payload or custom headers
	if !hasHostHeader {
		bb.B = append(bb.B, bHostColon...)
		bb.B = append(bb.B, bypassPayload.Host...)
		bb.B = append(bb.B, bCRLF...)
	}

	// Add standard headers (User-Agent, Accept)
	bb.B = append(bb.B, strUserAgentHeader...)
	bb.B = append(bb.B, bCRLF...)
	bb.B = append(bb.B, bAccept...)

	// Add Debug token if debug mode is enabled
	if GB403Logger.IsDebugEnabled() {
		bb.B = append(bb.B, bXGB403Token...)
		bb.B = append(bb.B, bypassPayload.PayloadToken...)
		bb.B = append(bb.B, bCRLF...)
	}

	// Add Content-Length header if body exists and wasn't explicitly set in payload
	if len(bypassPayload.Body) > 0 && !hasContentLength {
		bb.B = append(bb.B, bContentLength...)
		bb.B = append(bb.B, strconv.Itoa(len(bypassPayload.Body))...)
		bb.B = append(bb.B, bCRLF...)
	}

	// Add Connection header LAST, prioritizing payload's value if provided
	if !hasConnectionHeader { // Only add default if payload didn't specify one
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
