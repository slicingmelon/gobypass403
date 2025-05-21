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
	// Define shouldCloseConn based on general factors
	shouldCloseConn := httpclient.GetHTTPClientOptions().DisableKeepAlive ||
		httpclient.GetHTTPClientOptions().ProxyURL != "" ||
		bypassPayload.BypassModule == "headers_scheme" ||
		bypassPayload.BypassModule == "headers_ip" ||
		bypassPayload.BypassModule == "headers_port" ||
		bypassPayload.BypassModule == "headers_url" ||
		bypassPayload.BypassModule == "headers_host"

	// Get ByteBuffer from pool
	bb := requestBufferPool.Get()
	defer requestBufferPool.Put(bb)

	// Build request line directly into byte buffer
	bb.B = append(bb.B, bypassPayload.Method...)
	bb.B = append(bb.B, ' ')
	bb.B = append(bb.B, bypassPayload.RawURI...)
	bb.B = append(bb.B, " HTTP/1.1\r\n"...)

	// Track headers we've seen and will add
	// initialShouldCloseConn is the base value, currentShouldCloseConn will be updated by Connection headers.
	currentShouldCloseConn := shouldCloseConn

	hasHostHeader := false       // Will be true if Host is written
	hasContentLength := false    // Tracks if a normal Content-Length is set and written
	hasConnectionHeader := false // Tracks if Connection is set and written

	// Create a map to track which custom headers from client options we will add
	clientCustomHeadersMap := make(map[string]string)
	clientOpts := httpclient.GetHTTPClientOptions()
	if len(clientOpts.CustomHTTPHeaders) > 0 {
		for _, header := range clientOpts.CustomHTTPHeaders {
			colonIdx := strings.Index(header, ":")
			if colonIdx != -1 {
				headerName := strings.TrimSpace(header[:colonIdx])
				headerValue := strings.TrimSpace(header[colonIdx+1:])
				clientCustomHeadersMap[strings.ToLower(headerName)] = headerValue
				// Global has... flags are NOT set here anymore; they are set when headers are actually written.
			}
		}
	}

	// --- BEGIN Prioritized Header Writing ---
	handledByPriorityLogic := make(map[string]bool) // Tracks headers written in this section

	// 1. Host Header (Payload -> Custom -> Default)
	hostFromPayload := ""
	for _, h := range bypassPayload.Headers {
		if strings.EqualFold(h.Header, "Host") {
			hostFromPayload = h.Value
			break
		}
	}
	if hostFromPayload != "" {
		bb.B = append(bb.B, "Host: "...)
		bb.B = append(bb.B, hostFromPayload...)
		bb.B = append(bb.B, "\r\n"...)
		hasHostHeader = true
		delete(clientCustomHeadersMap, "host") // Remove from custom map as payload took precedence
	} else if customHost, exists := clientCustomHeadersMap["host"]; exists {
		bb.B = append(bb.B, "Host: "...)
		bb.B = append(bb.B, customHost...)
		bb.B = append(bb.B, "\r\n"...)
		hasHostHeader = true
	} else {
		bb.B = append(bb.B, "Host: "...)
		bb.B = append(bb.B, bypassPayload.Host...)
		bb.B = append(bb.B, "\r\n"...)
		hasHostHeader = true
	}
	handledByPriorityLogic["host"] = true

	// 2. User-Agent Header (Payload -> Custom -> Default)
	uaFromPayload := ""
	uaHeaderFromPayload := ""
	for _, h := range bypassPayload.Headers {
		if strings.EqualFold(h.Header, "User-Agent") {
			uaFromPayload = h.Value
			uaHeaderFromPayload = h.Header // Preserve original casing from payload
			break
		}
	}
	if uaFromPayload != "" {
		bb.B = append(bb.B, uaHeaderFromPayload...)
		bb.B = append(bb.B, ": "...)
		bb.B = append(bb.B, uaFromPayload...)
		bb.B = append(bb.B, "\r\n"...)
		delete(clientCustomHeadersMap, "user-agent")
	} else if customUA, exists := clientCustomHeadersMap["user-agent"]; exists {
		bb.B = append(bb.B, "User-Agent: "...) // Defaulting to standard casing
		bb.B = append(bb.B, customUA...)
		bb.B = append(bb.B, "\r\n"...)
	} else {
		bb.B = append(bb.B, strUserAgentHeader...)
		bb.B = append(bb.B, "\r\n"...)
	}
	handledByPriorityLogic["user-agent"] = true

	// 3. Accept Header (Payload -> Custom -> Default)
	acceptFromPayload := ""
	acceptHeaderFromPayload := ""
	for _, h := range bypassPayload.Headers {
		if strings.EqualFold(h.Header, "Accept") {
			acceptFromPayload = h.Value
			acceptHeaderFromPayload = h.Header
			break
		}
	}
	if acceptFromPayload != "" {
		bb.B = append(bb.B, acceptHeaderFromPayload...)
		bb.B = append(bb.B, ": "...)
		bb.B = append(bb.B, acceptFromPayload...)
		bb.B = append(bb.B, "\r\n"...)
		delete(clientCustomHeadersMap, "accept")
	} else if customAccept, exists := clientCustomHeadersMap["accept"]; exists {
		bb.B = append(bb.B, "Accept: "...) // Defaulting to standard casing
		bb.B = append(bb.B, customAccept...)
		bb.B = append(bb.B, "\r\n"...)
	} else {
		bb.B = append(bb.B, "Accept: */*\r\n"...)
	}
	handledByPriorityLogic["accept"] = true

	// 4. X-GB403-Token Header (Payload -> Custom -> Default, if debug)
	if GB403Logger.IsDebugEnabled() {
		tokenFromPayload := ""
		tokenHeaderFromPayload := ""
		for _, h := range bypassPayload.Headers {
			if strings.EqualFold(h.Header, "X-GB403-Token") {
				tokenFromPayload = h.Value
				tokenHeaderFromPayload = h.Header
				break
			}
		}
		if tokenFromPayload != "" {
			bb.B = append(bb.B, tokenHeaderFromPayload...)
			bb.B = append(bb.B, ": "...)
			bb.B = append(bb.B, tokenFromPayload...)
			bb.B = append(bb.B, "\r\n"...)
			delete(clientCustomHeadersMap, "x-gb403-token")
		} else if customToken, exists := clientCustomHeadersMap["x-gb403-token"]; exists {
			bb.B = append(bb.B, "X-GB403-Token: "...) // Defaulting to standard casing
			bb.B = append(bb.B, customToken...)
			bb.B = append(bb.B, "\r\n"...)
		} else {
			bb.B = append(bb.B, "X-GB403-Token: "...)
			bb.B = append(bb.B, bypassPayload.PayloadToken...)
			bb.B = append(bb.B, "\r\n"...)
		}
	}
	handledByPriorityLogic["x-gb403-token"] = true // Mark even if not debug, so main loops skip it.
	// --- END Prioritized Header Writing ---

	// Add remaining payload-specific headers (excluding those handled above)
	for _, h := range bypassPayload.Headers {
		if _, handled := handledByPriorityLogic[strings.ToLower(h.Header)]; handled {
			continue
		}

		// Check if this header is going to be overridden by a client custom header
		// (unless it's a critical exploit header like CL, Connection for this specific payload context)
		_, willBeOverriddenByCustom := clientCustomHeadersMap[strings.ToLower(h.Header)]

		if willBeOverriddenByCustom &&
			!(strings.EqualFold(h.Header, "Content-Length") || // Allow payload CL
				strings.HasPrefix(strings.ToLower(h.Header), "content-length0") || // Allow overflow CL
				strings.EqualFold(h.Header, "Connection")) { // Allow payload Connection
			// If overridden, and it's not one of the critical ones, the custom one will be added later.
			// So, we skip adding the payload version here.
			continue
		}

		// Set flags for special headers if set by payload
		if strings.EqualFold(h.Header, "Content-Length") {
			hasContentLength = true
			delete(clientCustomHeadersMap, "content-length") // Payload's CL takes precedence
		} else if strings.HasPrefix(strings.ToLower(h.Header), "content-length0") {
			// This is an exploit header, doesn't count as the 'normal' Content-Length
			// but ensure it's not deleted from custom map if it also exists there with same name by chance.
			// However, our exploit CL0 should take precedence.
			delete(clientCustomHeadersMap, strings.ToLower(h.Header))
		} else if strings.EqualFold(h.Header, "Connection") {
			hasConnectionHeader = true
			if strings.EqualFold(h.Value, "close") {
				currentShouldCloseConn = true
			} else if strings.EqualFold(h.Value, "keep-alive") {
				currentShouldCloseConn = false // Payload can force keep-alive
			}
			delete(clientCustomHeadersMap, "connection") // Payload's Connection takes precedence
		}

		// Append the header from the payload
		// Special handling for headers like "Content-Length0...a:" which should have an empty value part
		if strings.HasSuffix(h.Header, ":") && h.Value == "" {
			bb.B = append(bb.B, h.Header...) // Header name already includes the colon
			bb.B = append(bb.B, "\r\n"...)
		} else {
			bb.B = append(bb.B, h.Header...)
			bb.B = append(bb.B, ": "...)
			bb.B = append(bb.B, h.Value...)
			bb.B = append(bb.B, "\r\n"...)
		}
	}

	// Now add any client custom headers that weren't in the payload or handled by priority logic
	for headerNameLower, headerValue := range clientCustomHeadersMap {
		if _, handled := handledByPriorityLogic[headerNameLower]; handled {
			continue // Already handled by priority logic (e.g. Host, UA, Accept, Token)
		}

		// If payload set CL or Connection, custom versions are skipped (already deleted from map for these keys if payload set them)
		// For other headers, if they are still in map, they were not set by payload (or payload version was skipped due to custom override)

		// Capitalize first letter of each word for standard HTTP header format
		words := strings.Split(headerNameLower, "-")
		for i := range words {
			if len(words[i]) > 0 {
				words[i] = strings.ToUpper(words[i][:1]) + words[i][1:]
			}
		}
		headerName := strings.Join(words, "-")

		// Append the custom header
		bb.B = append(bb.B, headerName...)
		bb.B = append(bb.B, ": "...)
		bb.B = append(bb.B, headerValue...)
		bb.B = append(bb.B, "\r\n"...)

		// If this custom header is Content-Length or Connection, update flags
		if strings.EqualFold(headerName, "Content-Length") {
			hasContentLength = true
		} else if strings.EqualFold(headerName, "Connection") {
			hasConnectionHeader = true
			if strings.EqualFold(headerValue, "close") {
				currentShouldCloseConn = true
			} else if strings.EqualFold(headerValue, "keep-alive") {
				currentShouldCloseConn = false
			}
		}
	}

	// End of headers marker
	bb.B = append(bb.B, "\r\n"...)

	// Add body if present
	if len(bypassPayload.Body) > 0 {
		bb.B = append(bb.B, bypassPayload.Body...)
	}

	// Add Content-Length header for body if body exists AND no Content-Length was set from payload/custom
	if len(bypassPayload.Body) > 0 && !hasContentLength {
		bb.B = append(bb.B, "Content-Length: "...)
		bb.B = append(bb.B, []byte(strconv.Itoa(len(bypassPayload.Body)))...)
		bb.B = append(bb.B, "\r\n"...)
	}

	// Add Connection header if not set from payload/custom
	if !hasConnectionHeader {
		if currentShouldCloseConn {
			bb.B = append(bb.B, "Connection: close\r\n"...)
		} else {
			bb.B = append(bb.B, "Connection: keep-alive\r\n"...)
		}
	}

	// Get bufio.Reader from pool and reset it with our ByteBuffer reader
	br := rawRequestBuffReaderPool.Get().(*bufio.Reader)
	br.Reset(bytes.NewReader(bb.B))
	defer rawRequestBuffReaderPool.Put(br)

	req.URI().DisablePathNormalizing = true
	req.Header.DisableNormalizing()

	// Let FastHTTP parse the entire request (headers + body)
	if err := req.ReadLimitBody(br, 0); err != nil {
		return err
	}

	// Set URI components after successful parsing
	req.URI().DisablePathNormalizing = true
	req.Header.DisableNormalizing()
	req.Header.SetNoDefaultContentType(true)
	req.UseHostHeader = true

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
