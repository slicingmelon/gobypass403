// request.go
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/slicingmelon/go-rawurlparser"
	"golang.org/x/net/http2"
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
	client       *retryablehttp.Client
	client2      *http.Client
	errorHandler *ErrorHandler
	dialer       *fastdialer.Dialer
	Config       *Config
}

// initRawHTTPClient -- initializes the rawhttp client
func New() (*GO403BYPASS, error) {
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

		DialerTimeout:   time.Duration(config.Timeout) * time.Second,
		DialerKeepAlive: 10 * time.Second,

		CacheMemoryMaxItems: 200,
		WithDialerHistory:   true,
		WithCleanup:         true,

		WithZTLS:            true,
		DisableZtlsFallback: false,
		EnableFallback:      true,

		MaxTemporaryErrors:              30,
		MaxTemporaryToPermanentDuration: 1 * time.Minute,
	}

	dialer, err := fastdialer.NewDialer(fastdialerOpts)
	if err != nil {
		return nil, fmt.Errorf("could not create dialer: %v", err)
	}

	// Configure transport with fastdialer
	transport := &http.Transport{
		DialContext: dialer.Dial,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialTLS(ctx, network, addr)
		},
		DisableKeepAlives:   true,
		MaxIdleConnsPerHost: -1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
	}

	if !config.ForceHTTP2 {
		os.Setenv("GODEBUG", "http2client=0")
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}

	transport2 := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
		AllowHTTP:          true,
		DisableCompression: true,
	}

	// Add proxy if configured
	if config.ParsedProxy != nil {
		transport.Proxy = http.ProxyURL(config.ParsedProxy)
	}

	// Create base HTTP client with our custom transport
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.Timeout) * time.Second,
	}

	http2Client := &http.Client{
		Transport: transport2,
		Timeout:   time.Duration(config.Timeout) * time.Second,
	}

	// Configure retryablehttp options
	retryOpts := retryablehttp.Options{
		RetryWaitMin:    1 * time.Second,
		RetryWaitMax:    30 * time.Second,
		Timeout:         time.Duration(config.Timeout) * time.Second,
		RetryMax:        5,
		RespReadLimit:   4096,
		KillIdleConn:    true,
		NoAdjustTimeout: true,
		HttpClient:      httpClient, // Use our custom client with fastdialer
	}

	// Create retryablehttp client
	client := retryablehttp.NewClient(retryOpts)

	return &GO403BYPASS{
		client:       client,
		client2:      http2Client,
		dialer:       dialer,
		errorHandler: NewErrorHandler(),
		Config:       &config,
	}, nil
}

// SendRawRequestWithOptions sends a raw HTTP request with the given options
func (b *GO403BYPASS) SendRawRequestWithOptions(method, target, path string, headers map[string][]string, body io.Reader) (*http.Response, error) {
	// Convert headers map to http.Header
	httpHeaders := make(http.Header)
	for k, v := range headers {
		httpHeaders[k] = v
	}

	// Use rawhttp options
	options := rawhttp.DefaultOptions
	options.Timeout = time.Duration(b.Config.Timeout) * time.Second

	// Use the dialer from our client
	options.FastDialer = b.dialer

	// Add proxy if configured
	if b.Config.ParsedProxy != nil {
		options.Proxy = b.Config.ParsedProxy.String()
	}

	return rawhttp.DoRawWithOptions(method, target, path, httpHeaders, body, options)
}

// Close cleans up resources
func (b *GO403BYPASS) Close() {
	if b.client != nil && b.client.HTTPClient != nil {
		b.client.HTTPClient.CloseIdleConnections()
	}
	if b.client2 != nil {
		b.client2.CloseIdleConnections()
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
	return b.client != nil && b.errorHandler != nil
}

func (b *GO403BYPASS) sendRequest(method, rawURL string, headers []Header, bypassMode string) (*ResponseDetails, error) {
	if !b.IsInitialized() {
		return nil, fmt.Errorf("client not initialized")
	}

	if method == "" {
		method = "GET"
	}

	parsedURL, err := rawurlparser.RawURLParseWithError(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL %s: %v", rawURL, err)
	}

	// // Create retryablehttp request
	// req, err := retryablehttp.NewRequest(method, rawURL, nil)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to create request: %v", err)
	// }

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
		LogDebug("[%s] [Canary: %s] Sending request: %s [Headers: %s]\n",
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
		if rawBytes, err := rawhttp.DumpRequestRaw(method, target, fullPath, headerMap, nil, rawhttp.DefaultOptions); err != nil {
			LogError("[DumpRequestRaw] [%s] Failed to dump request %s -- Error: %v", bypassMode, targetFullURL, err)
		} else if rawBytes != nil {
			LogDebug("[DumpRequestRaw] [%s] Raw request:\n%s", bypassMode, string(rawBytes))
		}
	}

	// Use our new SendRawRequestWithOptions instead of global client
	resp, err := b.SendRawRequestWithOptions(method, target, fullPath, headerMap, nil)

	if err != nil {
		// Only handle "forcibly closed" errors with our custom logic
		if strings.Contains(err.Error(), "forcibly closed by the remote host") {
			err = b.errorHandler.HandleError(ErrForciblyClosed, parsedURL.Host)
		} else {
			if config.Debug {
				LogError("[sendRequest] [Canary: %s] [%s] Request Error on %s: %v\n",
					canary, bypassMode, targetFullURL, err)
			} else {
				LogError("[sendRequest] [%s] Request Error on %s: %v\n",
					bypassMode, targetFullURL, err)
			}
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
