// request.go
package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gcache"
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

type GO403BYPASS struct {
	rawClient    *rawhttp.Client
	errorHandler *ErrorHandler
	dialer       *fastdialer.Dialer
}

var (
	globalRawClient    *rawhttp.Client
	globalErrorHandler *ErrorHandler
	globalDialer       *fastdialer.Dialer
)

// initRawHTTPClient -- initializes the rawhttp client
func initRawHTTPClient() (*GO403BYPASS, error) {
	httpclient := &GO403BYPASS{}

	// Set fastdialer options from scratch
	fastdialerOpts := fastdialer.Options{
		BaseResolvers: []string{
			"1.1.1.1:53",
			"1.0.0.1:53",
			"9.9.9.10:53",
			"8.8.4.4:53",
		},
		MaxRetries:    5,
		HostsFile:     true,
		ResolversFile: true,
		CacheType:     fastdialer.Disk,
		DiskDbType:    fastdialer.LevelDB,

		// Timeouts
		DialerTimeout:   10 * time.Second,
		DialerKeepAlive: 10 * time.Second,

		// Cache settings
		CacheMemoryMaxItems: 200,
		WithDialerHistory:   true,
		WithCleanup:         true,

		// TLS settings
		WithZTLS:            true,
		DisableZtlsFallback: false,

		// Fallback settings
		EnableFallback: true,

		// Error handling
		MaxTemporaryErrors:              15,
		MaxTemporaryToPermanentDuration: 2 * time.Minute, // Our custom value (default was 1 minute)
	}

	// Use fastdialer
	var err error
	httpclient.dialer, err = fastdialer.NewDialer(fastdialerOpts)
	if err != nil {
		return nil, fmt.Errorf("could not create dialer: %v", err)
	}

	options := &rawhttp.Options{
		Timeout:                time.Duration(config.Timeout) * time.Second,
		FollowRedirects:        config.FollowRedirects,
		MaxRedirects:           map[bool]int{false: 0, true: 10}[config.FollowRedirects],
		AutomaticHostHeader:    false,
		AutomaticContentLength: true,
		ForceReadAllBody:       true,
		FastDialer:             httpclient.dialer,
	}

	if config.Proxy != "" {
		if !strings.HasPrefix(config.Proxy, "http://") && !strings.HasPrefix(config.Proxy, "https://") {
			config.Proxy = "http://" + config.Proxy
		}
		options.Proxy = config.Proxy
		options.ProxyDialTimeout = 10 * time.Second
	}

	httpclient.errorHandler = NewErrorHandler()
	httpclient.rawClient = rawhttp.NewClient(options)

	// Set globals
	globalRawClient = httpclient.rawClient
	globalErrorHandler = httpclient.errorHandler
	globalDialer = httpclient.dialer

	return httpclient, nil
}

// Close cleans up resources
func (b *GO403BYPASS) Close() {
	if b.rawClient != nil {
		b.rawClient.Close()
	}
	if b.dialer != nil {
		b.dialer.Close()
	}
	if b.errorHandler != nil {
		b.errorHandler.Purge()
	}
}

// Add a method to check if client is properly initialized
func (b *GO403BYPASS) IsInitialized() bool {
	return b.rawClient != nil && b.errorHandler != nil && b.dialer != nil
}

// ----------------------------------//
// Error Handling //
// ---------------------------------//
var (
	// Permanent errors
	ErrConnectionForciblyClosedPermanent = errkit.New("connection forcibly closed by remote host").
						SetKind(errkit.ErrKindNetworkPermanent).
						Build()

	// Temporary errors
	ErrConnectionForciblyClosedTemp = errkit.New("connection forcibly closed by remote host").
					SetKind(errkit.ErrKindNetworkTemporary).
					Build()
	ErrTLSHandshakeTemp = errkit.New("tls handshake error").
				SetKind(errkit.ErrKindNetworkTemporary).
				Build()
	ErrProxyTemp = errkit.New("proxy connection error").
			SetKind(errkit.ErrKindNetworkTemporary).
			Build()
)

// ErrorHandler manages error states and client lifecycle
type ErrorHandler struct {
	hostErrors       gcache.Cache[string, int]
	lastErrorTime    gcache.Cache[string, time.Time]
	maxErrors        int
	maxErrorDuration time.Duration
}

// NewErrorHandler creates a new error handler
func NewErrorHandler() *ErrorHandler {
	return &ErrorHandler{
		hostErrors: gcache.New[string, int](1000).
			ARC(). // Adaptive Replacement Cache
			Build(),
		lastErrorTime: gcache.New[string, time.Time](1000).
			ARC().
			Build(),
		maxErrors:        10,
		maxErrorDuration: 1 * time.Minute,
	}
}

// HandleError processes errors and determines if they're permanent
func (h *ErrorHandler) HandleError(err error, host string) error {
	if err == nil {
		return nil
	}

	// Get the error as errkit.ErrorX
	errx := errkit.FromError(err)

	// If it's already permanent, return as is
	if errx.Kind() == errkit.ErrKindNetworkPermanent {
		return errx
	}

	// Only handle temporary errors
	if errx.Kind() == errkit.ErrKindNetworkTemporary {
		now := time.Now()

		errorCount, _ := h.hostErrors.GetIFPresent(host)
		errorCount++
		_ = h.hostErrors.Set(host, errorCount)

		lastTime, _ := h.lastErrorTime.GetIFPresent(host)

		// Check if we're within the error window
		if !lastTime.IsZero() && now.Sub(lastTime) <= h.maxErrorDuration {
			if errorCount >= h.maxErrors {
				// Convert to permanent error
				errx.ResetKind().SetKind(errkit.ErrKindNetworkPermanent)
				return errkit.WithMessagef(errx.Build(),
					"max errors (%d) reached within %v for host %s",
					h.maxErrors, h.maxErrorDuration, host)
			}
		} else {
			// Reset counter if we're outside the window
			errorCount = 1
			_ = h.hostErrors.Set(host, errorCount)
		}

		// Update last error time
		_ = h.lastErrorTime.Set(host, now)
	}

	return errx.Build()
}

// Purge cleans up the caches
func (h *ErrorHandler) Purge() {
	h.hostErrors.Purge()
	h.lastErrorTime.Purge()
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
		if strings.Contains(err.Error(), "forcibly closed by the remote host") {
			err = errkit.Join(ErrConnectionForciblyClosedTemp, err)
		} else if strings.Contains(err.Error(), "tls") {
			err = errkit.Join(ErrTLSHandshakeTemp, err)
		} else if strings.Contains(err.Error(), "proxy") {
			err = errkit.Join(ErrProxyTemp, err)
		}

		// Let the error handler process it
		err = globalErrorHandler.HandleError(err, parsedURL.Host)
		if errkit.IsKind(err, errkit.ErrKindNetworkPermanent) {
			LogError("[%s] Permanent error detected for %s: %v\n",
				bypassMode, targetFullURL, err)
		} else {
			LogError("[%s] Temporary network error for %s: %v\n",
				bypassMode, targetFullURL, err)
		}
		return nil, err
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
