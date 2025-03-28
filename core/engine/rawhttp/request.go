// /*
// GoByPASS403
// Author: slicingmelon <github.com/slicingmelon>
// X: x.com/pedro_infosec
// */
// package rawhttp

// import (
// 	"bufio"
// 	"bytes"
// 	"strconv"
// 	"strings"
// 	"sync"

// 	"github.com/slicingmelon/gobypass403/core/engine/payload"

// 	"github.com/VictoriaMetrics/VictoriaMetrics/lib/bytesutil"
// 	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
// 	"github.com/valyala/fasthttp"
// )

// var (
// 	strUserAgentHeader = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
// )

// var (
// 	requestBufferPool = bytesutil.ByteBufferPool{}

// 	rawRequestBuffReaderPool = sync.Pool{
// 		New: func() any {
// 			return bufio.NewReader(nil)
// 		},
// 	}
// )

// // RawRequest just wraps a byte array for raw HTTP requests
// type RawRequest struct {
// 	Raw []byte
// }

// // Write implements the io.Writer interface
// func (r *RawRequest) Write(w *bufio.Writer) error {
// 	_, err := w.Write(r.Raw)
// 	return err
// }

// /*
// Crucial information

// Client determines the server to be requested in the following order:

//   - from RequestURI if it contains full url with scheme and host;
//   - from Host header otherwise.

// The function doesn't follow redirects. Use Get* for following redirects.
// Response is ignored if resp is nil.

// The detination/target URL is built based on req.URI, aka where the request will be sent to.

// Use req.URI().SetScheme("https") to set the scheme to https
// Use req.URI().SetHost("example.com") to set the target host -> this is where the request will be sent to
// Use req.SetRequestURI("/path") to set the path (e.g., / or /ssdaf).

// For spoofed/custom Host header!
// Set req.UseHostHeader = true to ensure the custom Host header is used instead of the URI host (fasthttp will extract it from the URI)
// Use req.Header.Set("Host", "evil.com") to set the spoofed Host header

// To set true raw request line, e.g. GET @evil.com HTTP/1.1, do not set req.SetRequestURI() and write the raw request line manually.

// For this to work, everything must be set in order, Raw Request line, headers, then appply settings,
// then set req.UseHostHeader = true and then req.URI().SetScheme() and req.URI().SetHost()
// */
// func BuildRawHTTPRequest(httpclient *HTTPClient, req *fasthttp.Request, bypassPayload payload.BypassPayload) error {
// 	// Get ByteBuffer from pool
// 	bb := requestBufferPool.Get()
// 	defer requestBufferPool.Put(bb)

// 	// Reset buffer
// 	bb.Reset()

// 	// Build request line
// 	bb.B = append(bb.B, bypassPayload.Method...)
// 	bb.B = append(bb.B, ' ')
// 	//bb.B = append(bb.B, bypassPayload.RawURI...)
// 	bb.B = append(bb.B, "/test"...)
// 	bb.B = append(bb.B, " HTTP/1.1\r\n"...)

// 	// Add Host header
// 	if bypassPayload.Host != "" {
// 		bb.B = append(bb.B, "Host: "...)
// 		bb.B = append(bb.B, bypassPayload.Host...)
// 		bb.B = append(bb.B, "\r\n"...)
// 	}

// 	// Flag to track if we need to add Connection: close
// 	shouldCloseConn := httpclient.options.DisableKeepAlive

// 	// Add remaining headers
// 	hasHostHeader := false
// 	hasContentLength := false
// 	for _, h := range bypassPayload.Headers {
// 		if strings.EqualFold(h.Header, "Host") {
// 			hasHostHeader = true
// 		} else if strings.EqualFold(h.Header, "Content-Length") {
// 			hasContentLength = true
// 		} else if strings.EqualFold(h.Header, "Connection") && strings.EqualFold(h.Value, "close") {
// 			shouldCloseConn = true
// 		}

// 		bb.B = append(bb.B, h.Header...)
// 		bb.B = append(bb.B, ": "...)
// 		bb.B = append(bb.B, h.Value...)
// 		bb.B = append(bb.B, "\r\n"...)
// 	}

// 	// Add host header if not already added
// 	if !hasHostHeader && bypassPayload.Host != "" {
// 		bb.B = append(bb.B, "Host: "...)
// 		bb.B = append(bb.B, bypassPayload.Host...)
// 		bb.B = append(bb.B, "\r\n"...)
// 	}

// 	// Default user agent unless explicitly disabled
// 	if !httpclient.options.NoDefaultUserAgent {
// 		bb.B = append(bb.B, "User-Agent: go-bypass-403\r\n"...)
// 	}

// 	// Add Accept header
// 	bb.B = append(bb.B, "Accept: */*\r\n"...)

// 	// Debug token
// 	if GB403Logger.IsDebugEnabled() {
// 		bb.B = append(bb.B, "X-GB403-Token: "...)
// 		bb.B = append(bb.B, bypassPayload.PayloadToken...)
// 		bb.B = append(bb.B, "\r\n"...)
// 	}

// 	// Add Content-Length header if body exists and header wasn't explicitly set
// 	if len(bypassPayload.Body) > 0 && !hasContentLength {
// 		bb.B = append(bb.B, "Content-Length: "...)
// 		bb.B = append(bb.B, strconv.Itoa(len(bypassPayload.Body))...)
// 		bb.B = append(bb.B, "\r\n"...)
// 	}

// 	// Add Connection header LAST
// 	if shouldCloseConn {
// 		bb.B = append(bb.B, "Connection: close\r\n"...)
// 	} else {
// 		bb.B = append(bb.B, "Connection: keep-alive\r\n"...)
// 	}

// 	// End of headers
// 	bb.B = append(bb.B, "\r\n"...)

// 	// Add body if present
// 	if len(bypassPayload.Body) > 0 {
// 		bb.B = append(bb.B, bypassPayload.Body...)
// 	}

// 	err := req.ReadLimitBody(bb.B, 0)
// 	if err != nil {
// 		GB403Logger.Error().Msgf("Failed to read request body: %v", err)
// 		return err
// 	}

// 	// Set minimal routing information for the connection
// 	req.URI().DisablePathNormalizing = true
// 	req.Header.DisableNormalizing()
// 	req.Header.SetNoDefaultContentType(true)
// 	req.UseHostHeader = true

// 	req.SetRequestURI(bypassPayload.RawURI)
// 	req.URI().SetScheme(bypassPayload.Scheme)
// 	req.URI().SetHost(bypassPayload.Host)

// 	if GB403Logger.IsDebugEnabled() {
// 		GB403Logger.Debug().Msgf("Built raw request:\n%s", req.String())
// 	}

// 	return nil
// }

// func applyReqFlags(req *fasthttp.Request) {
// 	req.URI().DisablePathNormalizing = true
// 	req.Header.DisableNormalizing()
// 	req.Header.SetNoDefaultContentType(true)
// 	req.UseHostHeader = true
// }

// func ReqCopyToWithSettings(src *fasthttp.Request, dst *fasthttp.Request) *fasthttp.Request {
// 	// Copy basic request data
// 	src.CopyTo(dst)

// 	// Log initial state after copy
// 	//GB403Logger.Debug().Msgf("After CopyTo - scheme=%s host=%s",
// 	//	src.URI().Scheme(), src.URI().Host()) // Use bytes directly in logging

// 	applyReqFlags(dst)

// 	// Store original values as []byte
// 	originalScheme := src.URI().Scheme()
// 	originalHost := src.URI().Host()

// 	//GB403Logger.Debug().Msgf("Original values - scheme=%s host=%s",
// 	//	originalScheme, originalHost) // Use bytes directly in logging

// 	// Use byte variants to avoid allocations
// 	dst.URI().SetSchemeBytes(originalScheme)
// 	dst.URI().SetHostBytes(originalHost)

// 	// Check if Host header exists using case-insensitive lookup
// 	if len(PeekRequestHeaderKeyCaseInsensitive(dst, strHostHeader)) == 0 {
// 		//GB403Logger.Debug().Msgf("No Host header found, setting from URI.Host: %s", originalHost)
// 		dst.Header.SetHostBytes(originalHost)
// 	}

// 	// GB403Logger.Debug().Msgf("After SetScheme/SetHost - scheme=%s host=%s header_host=%s",
// 	// 	dst.URI().Scheme(), dst.URI().Host(),
// 	// 	PeekRequestHeaderKeyCaseInsensitive(dst, hostKey))

// 	return dst
// }

// func PeekRequestHeaderKeyCaseInsensitive(h *fasthttp.Request, key []byte) []byte {
// 	var result []byte
// 	h.Header.VisitAll(func(k, v []byte) {
// 		if result == nil && bytes.EqualFold(k, key) {
// 			result = v
// 		}
// 	})
// 	return result
// }

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

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/bytesutil"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
	"github.com/valyala/fasthttp"
)

var (
	strUserAgentHeader = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
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
	// Define shouldCloseConn
	shouldCloseConn := len(bypassPayload.Headers) > 0 ||
		httpclient.GetHTTPClientOptions().DisableKeepAlive ||
		httpclient.GetHTTPClientOptions().ProxyURL != ""

	// Get ByteBuffer from pool
	bb := requestBufferPool.Get()
	defer requestBufferPool.Put(bb)

	// Build request line directly into byte buffer
	bb.B = append(bb.B, bypassPayload.Method...)
	bb.B = append(bb.B, ' ')
	//bb.B = append(bb.B, bypassPayload.RawURI...)
	bb.B = append(bb.B, "/test"...)
	bb.B = append(bb.B, " HTTP/1.1\r\n"...)

	// Add all headers
	hasHostHeader := false
	hasContentLength := false
	for _, h := range bypassPayload.Headers {
		if h.Header == "Host" {
			hasHostHeader = true
			shouldCloseConn = true
		}
		if h.Header == "Content-Length" {
			hasContentLength = true
		}
		if h.Header == "Connection" {
			// Skip Connection header here, we'll add it last
			shouldCloseConn = true
			continue
		}
		bb.B = append(bb.B, h.Header...)
		bb.B = append(bb.B, ": "...)
		bb.B = append(bb.B, h.Value...)
		bb.B = append(bb.B, "\r\n"...)
	}

	// Add Host header if not present
	if !hasHostHeader {
		bb.B = append(bb.B, "Host: "...)
		bb.B = append(bb.B, bypassPayload.Host...)
		bb.B = append(bb.B, "\r\n"...)
	}

	// Add standard headers
	bb.B = append(bb.B, strUserAgentHeader...)
	bb.B = append(bb.B, "\r\n"...)
	bb.B = append(bb.B, "Accept: */*\r\n"...)

	// Debug token
	if GB403Logger.IsDebugEnabled() {
		bb.B = append(bb.B, "X-GB403-Token: "...)
		bb.B = append(bb.B, bypassPayload.PayloadToken...)
		bb.B = append(bb.B, "\r\n"...)
	}

	// Add Content-Length header if body exists and header wasn't explicitly set
	if len(bypassPayload.Body) > 0 && !hasContentLength {
		bb.B = append(bb.B, "Content-Length: "...)
		bb.B = append(bb.B, strconv.Itoa(len(bypassPayload.Body))...)
		bb.B = append(bb.B, "\r\n"...)
	}

	// Add Connection header LAST
	if shouldCloseConn {
		bb.B = append(bb.B, "Connection: close\r\n"...)
	} else {
		bb.B = append(bb.B, "Connection: keep-alive\r\n"...)
	}

	// End of headers
	bb.B = append(bb.B, "\r\n"...)

	// Add body if present
	if len(bypassPayload.Body) > 0 {
		bb.B = append(bb.B, bypassPayload.Body...)
	}

	// Get bufio.Reader from pool and reset it with our ByteBuffer reader
	br := rawRequestBuffReaderPool.Get().(*bufio.Reader)
	br.Reset(bytes.NewReader(bb.B))
	defer rawRequestBuffReaderPool.Put(br)

	// Let FastHTTP parse the entire request (headers + body)
	if err := req.ReadLimitBody(br, 0); err != nil {
		return err
	}

	// Set URI components after successful parsing
	req.URI().DisablePathNormalizing = true
	req.Header.DisableNormalizing()
	req.Header.SetNoDefaultContentType(true)
	req.UseHostHeader = true

	req.SetRequestURI(bypassPayload.RawURI)

	req.URI().SetScheme(bypassPayload.Scheme)
	req.URI().SetHost(bypassPayload.Host)

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
	if len(PeekRequestHeaderKeyCaseInsensitive(dst, strHostHeader)) == 0 {
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
