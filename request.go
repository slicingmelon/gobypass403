// request.go
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"
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

var (
	globalRawClient *rawhttp.Client
	globalDialer    *fastdialer.Dialer
)

type GO403BYPASS struct {
	retryClient  *retryablehttp.Client
	errorHandler *ErrorHandler
	dialer       *fastdialer.Dialer
	config       *Config
	bypassMode   string // Track current bypass mode
}

// New creates a new GO403BYPASS instance
func New(cfg *Config, bypassMode string) (*GO403BYPASS, error) {
	client := &GO403BYPASS{
		config:     cfg,
		bypassMode: bypassMode,
	}

	// Initialize error handler
	client.errorHandler = NewErrorHandler()

	// Initialize fastdialer
	fastdialerOpts := fastdialer.Options{
		BaseResolvers: []string{
			"1.1.1.1:53", "1.0.0.1:53",
			"9.9.9.10:53", "8.8.4.4:53",
		},
		MaxRetries:     5,
		HostsFile:      true,
		ResolversFile:  true,
		CacheType:      fastdialer.Disk,
		DiskDbType:     fastdialer.LevelDB,
		DialerTimeout:  time.Duration(cfg.Timeout) * time.Second,
		WithZTLS:       true,
		EnableFallback: true,
	}

	var err error
	client.dialer, err = fastdialer.NewDialer(fastdialerOpts)
	if err != nil {
		return nil, fmt.Errorf("could not create dialer: %v", err)
	}

	// Create transport with our dialer
	transport := &http.Transport{
		DialContext:         client.dialer.Dial,
		DialTLSContext:      client.dialer.DialTLS,
		MaxIdleConnsPerHost: -1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
		DisableKeepAlives: true,
	}

	// Disable HTTP/2 if not forced
	if !cfg.ForceHTTP2 {
		os.Setenv("GODEBUG", "http2client=0")
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}

	// Create retryablehttp client
	retryOpts := retryablehttp.Options{
		RetryWaitMin: 1 * time.Second,
		RetryWaitMax: 30 * time.Second,
		RetryMax:     5,
		Timeout:      time.Duration(cfg.Timeout) * time.Second,
		KillIdleConn: true,
		HttpClient: &http.Client{
			Transport: transport,
			Timeout:   time.Duration(cfg.Timeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if !cfg.FollowRedirects {
					return http.ErrUseLastResponse
				}
				if len(via) >= 10 {
					return fmt.Errorf("stopped after 10 redirects")
				}
				return nil
			},
		},
	}

	client.retryClient = retryablehttp.NewClient(retryOpts)

	return client, nil
}

// Close cleans up resources
func (b *GO403BYPASS) Close() {
	if b.retryClient != nil {
		b.retryClient.HTTPClient.CloseIdleConnections()
	}
	if b.dialer != nil {
		b.dialer.Close()
	}
}

// NewRequest from url
func (b *GO403BYPASS) NewRawRequestFromURL(method, targetURL string) (*retryablehttp.Request, error) {
	return b.NewRawRequestFromURLWithContext(context.Background(), method, targetURL)
}

func (b *GO403BYPASS) NewRawRequestFromURLWithContext(ctx context.Context, method, targetURL string) (*retryablehttp.Request, error) {
	// Parse URL using urlutil with unsafe mode to preserve raw paths
	urlx, err := urlutil.ParseURL(targetURL, true)
	if err != nil {
		return nil, err
	}

	// Let retryablehttp handle the raw URL preservation
	req, err := retryablehttp.NewRequestFromURLWithContext(ctx, method, urlx, nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// sendRequest sends an HTTP request using retryablehttp
func (b *GO403BYPASS) sendRequest(method, rawURL string, headers []Header) (*ResponseDetails, error) {
	parsedURL, err := rawurlparser.RawURLParseWithError(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL %s: %v", rawURL, err)
	}

	LogVerbose("[sendRequest] [%s] RawURLParsed URL==> scheme:%s, host:%s, path:%s, query:%s\n",
		b.bypassMode, parsedURL.Scheme, parsedURL.Host, parsedURL.Path, parsedURL.Query)

	rawURLString := fmt.Sprintf("%s://%s%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path, parsedURL.Query)

	// Create request with tracing if debug is enabled
	var req *retryablehttp.Request
	if b.config.Debug {
		// Create base request
		httpReq, err := http.NewRequest(method, rawURLString, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create base request: %v", err)
		}

		// Create trace info
		trace := &httptrace.ClientTrace{
			GotConn: func(connInfo httptrace.GotConnInfo) {
				LogDebug("[Trace] [%s] Connection: Reused: %v, Was Idle: %v, Idle Time: %v\n",
					b.bypassMode, connInfo.Reused, connInfo.WasIdle, connInfo.IdleTime)
			},
			ConnectStart: func(network, addr string) {
				LogDebug("[Trace] [%s] Dial start: network: %s, address: %s\n",
					b.bypassMode, network, addr)
			},
			ConnectDone: func(network, addr string, err error) {
				LogDebug("[Trace] [%s] Dial done: network: %s, address: %s, err: %v\n",
					b.bypassMode, network, addr, err)
			},
			WroteHeaders: func() {
				LogDebug("[Trace] [%s] Wrote headers\n", b.bypassMode)
			},
			WroteRequest: func(wr httptrace.WroteRequestInfo) {
				LogDebug("[Trace] [%s] Wrote request, err: %v\n", b.bypassMode, wr.Err)
			},
			GotFirstResponseByte: func() {
				LogDebug("[Trace] [%s] Got first response byte\n", b.bypassMode)
			},
		}

		// Add trace to context
		httpReq = httpReq.WithContext(httptrace.WithClientTrace(httpReq.Context(), trace))

		// Convert to retryablehttp.Request
		req, err = retryablehttp.FromRequest(httpReq)
		if err != nil {
			return nil, fmt.Errorf("failed to create traced request: %v", err)
		}
	} else {
		// Normal request creation without tracing
		req, err = b.NewRawRequestFromURL(method, rawURLString)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %v", err)
		}
	}

	// Add headers
	for _, h := range headers {
		req.Header.Set(h.Key, h.Value)
	}

	// Debug canary
	if b.config.Debug {
		canary := generateRandomString(18)
		req.Header.Set("X-Go-Bypass-403", canary)
		LogDebug("[sendRequest] [%s] [Canary: %s] Sending request: %s [Headers: %s]\n",
			b.bypassMode,
			canary,
			rawURLString,
			formatHeaders(headers),
		)
	}

	// Send request
	resp, err := b.retryClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Process response
	headersCopy := resp.Header.Clone()

	// Skip if status code doesn't match
	if !contains(b.config.MatchStatusCodes, resp.StatusCode) {
		return &ResponseDetails{
			StatusCode: resp.StatusCode,
		}, nil
	}

	details := &ResponseDetails{
		StatusCode:    resp.StatusCode,
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: resp.ContentLength,
		ServerInfo:    resp.Header.Get("Server"),
		RedirectURL:   resp.Header.Get("Location"),
	}

	// Get raw headers
	respHeaders, err := GetResponseHeadersRaw(resp)
	if err != nil {
		LogVerbose("[%s] Failed to dump response headers: %v", b.bypassMode, err)
	} else {
		details.ResponseHeaders = string(respHeaders)
	}

	// Read body for applicable status codes
	if resp.StatusCode != http.StatusSwitchingProtocols &&
		resp.StatusCode != http.StatusNotModified &&
		resp.StatusCode != http.StatusMovedPermanently {

		bodyBytes, err := GetResponseBodyRaw(resp, headersCopy, 1024)
		if err != nil {
			details.ResponsePreview = "<failed to read response body>"
			details.ResponseBytes = 0
		} else {
			details.ResponseBytes = len(bodyBytes)
			details.ResponsePreview = string(bodyBytes)
		}
	}

	// Debug logging
	if b.config.Verbose {
		LogYellow("=====> Response Details for URL %s\n", req.URL.String())
		LogYellow("Status: %d %s\n", resp.StatusCode, resp.Status)
		LogYellow("Headers:\n%s\n", details.ResponseHeaders)
		LogYellow("Body (%d bytes):\n%s\n", details.ResponseBytes, details.ResponsePreview)
		LogYellow("=====> End of Response Details\n")
	}

	if b.config.Debug {
		// Log the exact URL before and after retryablehttp processing
		LogDebug("[%s] Original URL: %s", b.bypassMode, rawURL)
		LogDebug("[%s] Processed URL: %s", b.bypassMode, req.URL.String())
	}

	return details, nil
}

// // initRawHTTPClient -- initializes the rawhttp client
// func initRawHTTPClient() (*GO403BYPASS, error) {
// 	httpclient := &GO403BYPASS{}

// 	// Set fastdialer options from scratch
// 	fastdialerOpts := fastdialer.Options{
// 		BaseResolvers: []string{
// 			"1.1.1.1:53",
// 			"1.0.0.1:53",
// 			"9.9.9.10:53",
// 			"8.8.4.4:53",
// 		},
// 		MaxRetries:    5,
// 		HostsFile:     true,
// 		ResolversFile: true,
// 		CacheType:     fastdialer.Disk,
// 		DiskDbType:    fastdialer.LevelDB,

// 		// Timeouts
// 		DialerTimeout:   time.Duration(config.Timeout) * time.Second,
// 		DialerKeepAlive: 10 * time.Second,

// 		// Cache settings
// 		CacheMemoryMaxItems: 200,
// 		WithDialerHistory:   true,
// 		WithCleanup:         true,

// 		// TLS settings
// 		WithZTLS:            true,
// 		DisableZtlsFallback: false,

// 		// Fallback settings
// 		EnableFallback: true,

// 		SNIName: "", // ??

// 		// Error handling
// 		MaxTemporaryErrors:              30,
// 		MaxTemporaryToPermanentDuration: 1 * time.Minute, // Our custom value (default was 1 minute)
// 	}

// 	// Use fastdialer
// 	var err error
// 	httpclient.dialer, err = fastdialer.NewDialer(fastdialerOpts)
// 	if err != nil {
// 		return nil, fmt.Errorf("could not create dialer: %v", err)
// 	}

// 	options := &rawhttp.Options{
// 		Timeout:                time.Duration(config.Timeout) * time.Second,
// 		FollowRedirects:        config.FollowRedirects,
// 		MaxRedirects:           map[bool]int{false: 0, true: 10}[config.FollowRedirects],
// 		AutomaticHostHeader:    false,
// 		AutomaticContentLength: true,
// 		ForceReadAllBody:       true,
// 		FastDialer:             httpclient.dialer,
// 	}

// 	if config.Proxy != "" {
// 		if !strings.HasPrefix(config.Proxy, "http://") && !strings.HasPrefix(config.Proxy, "https://") {
// 			config.Proxy = "http://" + config.Proxy
// 		}
// 		options.Proxy = config.Proxy
// 		options.ProxyDialTimeout = 10 * time.Second
// 	}

// 	httpclient.errorHandler = NewErrorHandler()
// 	httpclient.rawClient = rawhttp.NewClient(options)

// 	// Set globals
// 	globalRawClient = httpclient.rawClient
// 	globalErrorHandler = httpclient.errorHandler
// 	globalDialer = httpclient.dialer

// 	return httpclient, nil
// }

// // Close cleans up resources
// func (b *GO403BYPASS) Close() {
// 	if b.rawClient != nil {
// 		b.rawClient.Close()
// 	}
// 	if b.errorHandler != nil {
// 		b.errorHandler.Purge()
// 	}
// }

// Add a method to check if client is properly initialized
// func (b *GO403BYPASS) IsInitialized() bool {
// 	return b.rawClient != nil && b.errorHandler != nil
// }

// func (b *GO403BYPASS) sendRequest(method, rawURL string, headers []Header) (*ResponseDetails, error) {
// 	if needsRawHTTP(b.bypassMode) {
// 		return b.sendRawRequest(method, rawURL, headers)
// 	}
// 	return b.sendRetryableRequest(method, rawURL, headers)
// }

// func (b *GO403BYPASS) sendRetryableRequest(method, rawURL string, headers []Header) (*ResponseDetails, error) {
// 	// Create request
// 	req, err := retryablehttp.NewRequest(method, rawURL, nil)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create request: %v", err)
// 	}

// 	// Add headers
// 	for _, h := range headers {
// 		req.Header.Set(h.Key, h.Value)
// 	}

// 	// Debug canary
// 	if b.config.Debug {
// 		canary := generateRandomString(18)
// 		req.Header.Set("X-Go-Bypass-403", canary)
// 	}

// 	// Send request
// 	resp, err := b.retryClient.Do(req)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer resp.Body.Close()

// 	// Process response
// 	return processResponse(resp, b.config, b.bypassMode)
// }

// // Helper to convert retryablehttp headers to our Header type
// func headersFromRetryableRequest(req *retryablehttp.Request) []Header {
// 	headers := make([]Header, 0)
// 	for k, v := range req.Header {
// 		if len(v) > 0 {
// 			headers = append(headers, Header{
// 				Key:   k,
// 				Value: v[0],
// 			})
// 		}
// 	}
// 	return headers
// }

// func sendRequest(method, rawURL string, headers []Header, bypassMode string) (*ResponseDetails, error) {
// 	if method == "" {
// 		method = "GET"
// 	}

// 	parsedURL, err := rawurlparser.RawURLParseWithError(rawURL)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse URL %s: %v", rawURL, err)
// 	}

// 	LogVerbose("[sendRequest] [%s] Parsed URL==> scheme:%s, host:%s, path:%s, query:%s\n",
// 		bypassMode, parsedURL.Scheme, parsedURL.Host, parsedURL.Path, parsedURL.Query)

// 	// Headers stuff
// 	canary := generateRandomString(18)
// 	orderedHeaders := make([]Header, 0)

// 	// Prioritize Host header if provided
// 	for _, h := range headers {
// 		if strings.EqualFold(h.Key, "Host") {
// 			orderedHeaders = append(orderedHeaders, h)
// 			break
// 		}
// 	}

// 	// Set default Host if not provided
// 	if !containsHeader(orderedHeaders, "Host") {
// 		orderedHeaders = append(orderedHeaders, Header{
// 			Key:   "Host",
// 			Value: parsedURL.Host,
// 		})
// 	}

// 	// Add remaining headers, skipping duplicates
// 	for _, h := range headers {
// 		if !containsHeader(orderedHeaders, h.Key) {
// 			orderedHeaders = append(orderedHeaders, h)
// 		}
// 	}

// 	// Ensure User-Agent
// 	if !containsHeader(orderedHeaders, "User-Agent") {
// 		orderedHeaders = append(orderedHeaders, Header{
// 			Key:   "User-Agent",
// 			Value: defaultUserAgent,
// 		})
// 	}

// 	// Add X-Go-Bypass header with canary when debug is enabled
// 	if config.Debug {
// 		orderedHeaders = append(orderedHeaders, Header{
// 			Key:   "X-Go-Bypass-403",
// 			Value: canary,
// 		})
// 	}

// 	// Always add Connection: close at the end
// 	// if !containsHeader(orderedHeaders, "Connection") {
// 	// 	orderedHeaders = append(orderedHeaders, Header{
// 	// 		Key:   "Connection",
// 	// 		Value: "close",
// 	// 	})
// 	// }

// 	// Convert to map for rawhttp
// 	headerMap := make(map[string][]string)
// 	for _, h := range orderedHeaders {
// 		headerMap[h.Key] = []string{h.Value}
// 	}

// 	// target URL
// 	target := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

// 	// Construct full path with query
// 	fullPath := parsedURL.Path
// 	if parsedURL.Query != "" {
// 		fullPath += "?" + parsedURL.Query
// 	}

// 	targetFullURL := target + fullPath

// 	// Official logging final
// 	if config.Debug {
// 		requestLine := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, fullPath)
// 		LogDebug("[%s] [Canary: %s] Sending request: %s [Headers: %s]\n",
// 			bypassMode,
// 			canary,
// 			requestLine,
// 			formatHeaders(orderedHeaders))
// 	} else if isVerbose {
// 		LogVerbose("[%s] Sending request: %s%s [Headers: %s]\n",
// 			bypassMode,
// 			target,
// 			fullPath,
// 			formatHeaders(orderedHeaders))
// 	}

// 	// Debug logging
// 	if config.Debug {
// 		rawBytes, err := rawhttp.DumpRequestRaw(method, target, fullPath, headerMap, nil, globalRawClient.Options)
// 		if err != nil {
// 			LogError("[DumpRequestRaw] [%s] Failed to dump request: %v\n", bypassMode, err)
// 		} else {
// 			LogDebug("[DumpRequestRaw] [%s] Raw request:\n%s\n", bypassMode, string(rawBytes))
// 		}
// 	}

// 	// raw requests boys..
// 	// Use global client
// 	resp, err := globalRawClient.DoRawWithOptions(method, target, fullPath, headerMap, nil, globalRawClient.Options)

// 	if err != nil {
// 		// Only handle "forcibly closed" errors with our custom logic
// 		if strings.Contains(err.Error(), "forcibly closed by the remote host") {
// 			err = globalErrorHandler.HandleError(ErrForciblyClosed, parsedURL.Host)
// 		} else {
// 			if config.Debug {
// 				LogError("[sendRequest] [Canary: %s] [%s] Request Error on %s: %v\n",
// 					canary, bypassMode, targetFullURL, err)
// 			} else {
// 				LogError("[sendRequest] [%s] Request Error on %s: %v\n",
// 					bypassMode, targetFullURL, err)
// 			}
// 		}

// 		return nil, err
// 	}
// 	// Keep a copy of headers for safety and for GetResponseBodyRaw later
// 	headersCopy := resp.Header.Clone()

// 	// Skip processing if HTTP status code doesn't match cli input
// 	if !contains(config.MatchStatusCodes, resp.StatusCode) {
// 		resp.Body.Close()
// 		return &ResponseDetails{
// 			StatusCode: resp.StatusCode,
// 		}, nil
// 	}

// 	// Initialize ResponseDetails immediately
// 	details := &ResponseDetails{
// 		StatusCode:    resp.StatusCode,
// 		ContentType:   resp.Header.Get("Content-Type"),
// 		ContentLength: resp.ContentLength,
// 		ServerInfo:    resp.Header.Get("Server"),
// 		RedirectURL:   resp.Header.Get("Location"),
// 	}

// 	// Get raw response headers first
// 	respHeaders, err := GetResponseHeadersRaw(resp)
// 	if err != nil {
// 		LogVerbose("[%s] Failed to dump response headers for %s: %v", bypassMode, targetFullURL, err)
// 	} else {
// 		details.ResponseHeaders = string(respHeaders)
// 		// Try to get content type from raw headers if not found in normalized headers
// 		if details.ContentType == "" {
// 			// Simple case-insensitive search in raw headers
// 			rawHeaders := strings.ToLower(string(respHeaders))
// 			if idx := strings.Index(rawHeaders, "content-type:"); idx >= 0 {
// 				endIdx := strings.Index(rawHeaders[idx:], "\r\n")
// 				if endIdx > 0 {
// 					ct := rawHeaders[idx+13 : idx+endIdx]
// 					details.ContentType = strings.TrimSpace(ct)
// 				}
// 			}
// 		}
// 	}

// 	// Don't read body for certain status codes
// 	if resp.StatusCode != http.StatusSwitchingProtocols &&
// 		resp.StatusCode != http.StatusNotModified &&
// 		resp.StatusCode != http.StatusMovedPermanently {

// 		bodyBytes, err := GetResponseBodyRaw(resp, headersCopy, 1024)
// 		if err != nil {
// 			LogVerbose("[%s] Failed to read response body for %s: %v", bypassMode, targetFullURL, err)
// 			details.ResponsePreview = "<failed to read response body>"
// 			details.ResponseBytes = 0
// 		} else {
// 			details.ResponseBytes = len(bodyBytes)

// 			// Set preview to raw bytes even if decoding failed
// 			details.ResponsePreview = string(bodyBytes)

// 			// Handle Content-Length separately from ResponseBytes
// 			if cl := headersCopy.Get("Content-Length"); cl != "" {
// 				if clInt, err := strconv.ParseInt(cl, 10, 64); err == nil {
// 					details.ContentLength = clInt
// 				}
// 			}

// 			if details.ContentLength <= 0 {
// 				details.ContentLength = resp.ContentLength
// 			}
// 		}
// 	}

// 	// Close body after reading
// 	if closeErr := resp.Body.Close(); closeErr != nil {
// 		LogVerbose("[%s] Failed to close response body for %s: %v", bypassMode, targetFullURL, closeErr)
// 	}

// 	// Debug logging
// 	if config.Verbose {
// 		LogYellow("=====> Response Details for URL %s\n", targetFullURL)
// 		LogYellow("Status: %d %s\n", resp.StatusCode, resp.Status)
// 		LogYellow("Headers:\n%s\n", details.ResponseHeaders)
// 		LogYellow("Body (%d bytes):\n%s\n", details.ResponseBytes, details.ResponsePreview)
// 		LogYellow("=====> End of Response Details\n")
// 	}

// 	return details, nil
// }

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

func containsHeader(headers []Header, key string, sensitive ...bool) bool {
	isCaseSensitive := false
	if len(sensitive) > 0 {
		isCaseSensitive = sensitive[0]
	}

	if isCaseSensitive {
		for _, h := range headers {
			if h.Key == key {
				return true
			}
		}
		return false
	}

	lowercaseKey := strings.ToLower(key)
	for _, h := range headers {
		if strings.ToLower(h.Key) == lowercaseKey {
			return true
		}
	}
	return false
}

func (b *GO403BYPASS) validateRequest(req *retryablehttp.Request) error {
	// Verify URL structure preservation
	// Check header ordering if critical
	// Validate any bypass-specific requirements
	return nil
}
