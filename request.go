// request.go
package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"

	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/utils/errkit"
	"github.com/slicingmelon/go-rawurlparser"
)

type Header struct {
	Key   string
	Value string
}

type ResponseDetails struct {
	StatusCode      int
	ResponsePreview string
	ResponseHeaders string
	ContentType     string
	ContentLength   int64
	ServerInfo      string
	RedirectURL     string
	ResponseBytes   int
	Title           string
}

func sendRequest(method, rawURL string, headers []Header, bypassMode string) (*ResponseDetails, error) {
	if method == "" {
		method = "GET"
	}

	parsedURL, err := rawurlparser.RawURLParseWithError(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL %s: %v", rawURL, err)
	}

	LogVerbose("[sendRequest] [%s] Parsed URL: scheme=%s, host=%s, path=%s, query=%s\n",
		bypassMode, parsedURL.Scheme, parsedURL.Host, parsedURL.Path, parsedURL.Query)

	// Headers stuff
	var canary string
	headerMap := make(map[string][]string)
	for _, h := range headers {
		headerMap[h.Key] = []string{h.Value}
	}
	if _, exists := headerMap["Host"]; !exists {
		headerMap["Host"] = []string{parsedURL.Host}
	}
	if _, exists := headerMap["User-Agent"]; !exists {
		headerMap["User-Agent"] = []string{defaultUserAgent}
	}
	// Add debug canary
	if config.Debug {
		canary = generateRandomString(18)
		headerMap["X-Go-Bypass-403"] = []string{canary}
	}

	// raw requests boys..
	// if _, exists := headerMap["Accept"]; !exists {
	// 	headerMap["Accept"] = []string{"*/*"}
	// }
	if _, exists := headerMap["Accept-Encoding"]; !exists {
		headerMap["Accept-Encoding"] = []string{"gzip"} // Removed br as we don't handle brotli yet
	}

	if _, exists := headerMap["Accept-Charset"]; !exists {
		headerMap["Accept-Charset"] = []string{"utf-8"}
	}

	// target URL
	target := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// Construct full path with query
	fullPath := parsedURL.Path
	if parsedURL.Query != "" {
		fullPath += "?" + parsedURL.Query
	}

	targetFullURL := target + fullPath

	// Official logging final
	if config.Debug {
		requestLine := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, fullPath)
		LogDebug("[%s] [Canary:%s] Sending request: %s [Headers: %s]\n",
			bypassMode,
			canary,
			requestLine,
			formatHeaders(headers))
	} else if isVerbose {
		LogVerbose("[%s] Sending request: %s%s [Headers: %s]\n",
			bypassMode,
			target,
			fullPath,
			formatHeaders(headers))
	}

	// Debug logging
	if config.Debug {
		rawBytes, err := rawhttp.DumpRequestRaw(method, target, fullPath, headerMap, nil, globalRawClient.Options)
		if err != nil {
			LogError("[%s] Failed to dump request %s -- Error: %v", bypassMode, targetFullURL, err)
		} else {
			LogDebug("[sendRequest] [%s] Raw request:\n%s", bypassMode, string(rawBytes))
		}
	}

	// Use global client
	resp, err := globalRawClient.DoRawWithOptions(method, target, fullPath, headerMap, nil, globalRawClient.Options)

	if err != nil {
		if strings.Contains(err.Error(), "proxy") {
			LogError("[%s] Proxy error for %s: %v\n", bypassMode, targetFullURL, err)
		} else if strings.Contains(err.Error(), "tls") {
			LogError("[%s] TLS error for %s: %v\n", bypassMode, targetFullURL, err)
		} else if strings.Contains(err.Error(), "forcibly closed by the remote host") {
			// Let fastdialer handle the error counting by wrapping with temporary kind
			errx := errkit.New("connection forcibly closed by the remote host").
				SetKind(errkit.ErrKindNetworkTemporary).
				Build()

			LogError("[%s] Network error for %s: errKind=%s %v\n",
				bypassMode, targetFullURL, errkit.ErrKindNetworkTemporary, err)

			return nil, errx
		} else {
			LogError("[%s] Request error for %s: %v\n", bypassMode, targetFullURL, err)
			return nil, err
		}
	}
	// Keep a copy of headers for safety and for GetResponseBodyRaw later
	headersCopy := resp.Header.Clone()

	// Skip processing if HTTP status code doesn't match cli input
	if !contains(config.MatchStatusCodes, resp.StatusCode) {
		resp.Body.Close()
		return &ResponseDetails{
			StatusCode: resp.StatusCode,
		}, nil
	}

	// Initialize ResponseDetails immediately
	details := &ResponseDetails{
		StatusCode:    resp.StatusCode,
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: resp.ContentLength,
		ServerInfo:    resp.Header.Get("Server"),
		RedirectURL:   resp.Header.Get("Location"),
	}

	// Get raw response headers first
	respHeaders, err := GetResponseHeadersRaw(resp)
	if err != nil {
		LogVerbose("[%s] Failed to dump response headers for %s: %v", bypassMode, targetFullURL, err)
	} else {
		details.ResponseHeaders = string(respHeaders)
		// Try to get content type from raw headers if not found in normalized headers
		if details.ContentType == "" {
			// Simple case-insensitive search in raw headers
			rawHeaders := strings.ToLower(string(respHeaders))
			if idx := strings.Index(rawHeaders, "content-type:"); idx >= 0 {
				endIdx := strings.Index(rawHeaders[idx:], "\r\n")
				if endIdx > 0 {
					ct := rawHeaders[idx+13 : idx+endIdx]
					details.ContentType = strings.TrimSpace(ct)
				}
			}
		}
	}

	// Don't read body for certain status codes
	if resp.StatusCode != http.StatusSwitchingProtocols &&
		resp.StatusCode != http.StatusNotModified &&
		resp.StatusCode != http.StatusMovedPermanently {

		bodyBytes, err := GetResponseBodyRaw(resp, headersCopy, 1024)
		if err != nil {
			LogVerbose("[%s] Failed to read response body for %s: %v", bypassMode, targetFullURL, err)
			details.ResponsePreview = "<failed to read response body>"
			details.ResponseBytes = 0
		} else {
			details.ResponseBytes = len(bodyBytes)

			// Set preview to raw bytes even if decoding failed
			details.ResponsePreview = string(bodyBytes)

			// Handle Content-Length separately from ResponseBytes
			if cl := headersCopy.Get("Content-Length"); cl != "" {
				if clInt, err := strconv.ParseInt(cl, 10, 64); err == nil {
					details.ContentLength = clInt
				}
			}

			if details.ContentLength <= 0 {
				details.ContentLength = resp.ContentLength
			}
		}
	}

	// Close body after reading
	if closeErr := resp.Body.Close(); closeErr != nil {
		LogVerbose("[%s] Failed to close response body for %s: %v", bypassMode, targetFullURL, closeErr)
	}

	// Debug logging
	if config.Verbose {
		LogYellow("=====> Response Details for URL %s\n", targetFullURL)
		LogYellow("Status: %d %s\n", resp.StatusCode, resp.Status)
		LogYellow("Headers:\n%s\n", details.ResponseHeaders)
		LogYellow("Body (%d bytes):\n%s\n", details.ResponseBytes, details.ResponsePreview)
		LogYellow("=====> End of Response Details\n")
	}

	return details, nil
}

func GetResponseHeadersRaw(resp *http.Response) ([]byte, error) {
	// Handle 1xx responses
	if resp.StatusCode >= http.StatusContinue && resp.StatusCode <= http.StatusEarlyHints {
		raw := resp.Status + "\n"
		for h, v := range resp.Header {
			raw += fmt.Sprintf("%s: %s\n", h, v)
		}
		return []byte(raw), nil
	}

	headers, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return nil, fmt.Errorf("failed to dump response headers: %v", err)
	}
	return headers, nil
}

// GetResponseBodyRaw reads the response body with size limits and attempts to decode it
// headersCopy should be a clone of the original response headers to ensure thread-safety
func GetResponseBodyRaw(resp *http.Response, headersCopy http.Header, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 4096 // Default to 4KB if not specified
	}

	// Read directly up to maxBytes
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		// Don't fail completely on read errors, return what we have
		if len(bodyBytes) > 0 {
			return bodyBytes, nil
		}
		return nil, err
	}

	// Try to decode the response using the copied headers
	decodedBody, err := httpx.DecodeData(bodyBytes, headersCopy)
	if err != nil {
		// If decoding fails, return the raw bytes
		return bodyBytes, nil
	}

	return decodedBody, nil
}

func contains(codes []int, code int) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}
