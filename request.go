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

	// Create retryablehttp client with tracing enabled if debug mode is on
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
		Trace: cfg.TraceRequests, // Enable tracing if debug is enabled
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

// NewRawRequestFromURLWithContext creates a request with optional tracing while preserving raw paths
func (b *GO403BYPASS) NewRawRequestFromURLWithContext(ctx context.Context, method, targetURL string) (*retryablehttp.Request, error) {
	// Parse URL using urlutil with unsafe mode to preserve raw paths
	urlx, err := urlutil.ParseURL(targetURL, true)
	if err != nil {
		return nil, err
	}

	if b.config.Debug {
		LogDebug("[NewRawRequestFromURLWithContext] [%s] Original URL: %s, Processed URL: %s",
			b.bypassMode,
			urlx.Original, // This preserves the exact original URL
			urlx.String()) // This is the processed/normalized version
	}
	// Create request using retryablehttp
	req, err := retryablehttp.NewRequestFromURLWithContext(ctx, method, urlx, nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewRawRequestFromURL is a convenience wrapper around NewRawRequestFromURLWithContext
func (b *GO403BYPASS) NewRawRequestFromURL(method, targetURL string) (*retryablehttp.Request, error) {
	return b.NewRawRequestFromURLWithContext(context.Background(), method, targetURL)
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

	if b.config.Debug {
		// Log the exact URL before and after retryablehttp processing
		LogDebug("[sendRequest] [%s] Original URL: %s", b.bypassMode, rawURLString)
	}

	// Create request
	req, err := b.NewRawRequestFromURL(method, rawURLString)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	if !containsHeader(headers, "User-Agent") {
		req.Header.Set("User-Agent", defaultUserAgent)
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

	// Add the rest of HTTP headers
	for _, h := range headers {
		req.Header.Set(h.Key, h.Value)
	}

	// Send request
	resp, err := b.retryClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Log trace info if debug is enabled
	if b.config.TraceRequests && req.TraceInfo != nil {
		logTraceInfo(b.bypassMode, req.TraceInfo)
	}

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
		LogYellow("=====> Response Details for URL %s\n", rawURLString)
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

func logTraceInfo(bypassMode string, traceInfo *retryablehttp.TraceInfo) {
	if traceInfo.GetConn.Time.IsZero() {
		return
	}

	var trace strings.Builder
	trace.WriteString(fmt.Sprintf("[Trace] [%s] Connection Details:\n", bypassMode))

	// Connection Info
	if info, ok := traceInfo.GotConn.Info.(httptrace.GotConnInfo); ok {
		trace.WriteString(fmt.Sprintf("  Connection: Reused=%v, WasIdle=%v, IdleTime=%v\n",
			info.Reused, info.WasIdle, info.IdleTime))
	}

	// DNS Info
	if info, ok := traceInfo.DNSDone.Info.(httptrace.DNSDoneInfo); ok {
		trace.WriteString(fmt.Sprintf("  DNS: Addresses=%v, Coalesced=%v, Err=%v\n",
			info.Addrs, info.Coalesced, info.Err))
	}

	// Connection Details
	if info, ok := traceInfo.ConnectStart.Info.(struct{ Network, Addr string }); ok {
		trace.WriteString(fmt.Sprintf("  Network: %s, Remote Address: %s\n",
			info.Network, info.Addr))
	}

	// TLS Info
	if info, ok := traceInfo.TLSHandshakeDone.Info.(struct {
		ConnectionState tls.ConnectionState
		Error           error
	}); ok {
		trace.WriteString(fmt.Sprintf("  TLS: Version=%x, CipherSuite=%x, ServerName=%s\n",
			info.ConnectionState.Version,
			info.ConnectionState.CipherSuite,
			info.ConnectionState.ServerName))
	}

	// Request Write Info
	if info, ok := traceInfo.WroteRequest.Info.(httptrace.WroteRequestInfo); ok && info.Err != nil {
		trace.WriteString(fmt.Sprintf("  Request Write Error: %v\n", info.Err))
	}

	// Timing Info
	dnsTime := traceInfo.DNSDone.Time.Sub(traceInfo.DNSStart.Time)
	connTime := traceInfo.ConnectDone.Time.Sub(traceInfo.ConnectStart.Time)
	tlsTime := traceInfo.TLSHandshakeDone.Time.Sub(traceInfo.TLSHandshakeStart.Time)
	responseTime := traceInfo.GotFirstResponseByte.Time.Sub(traceInfo.WroteRequest.Time)

	trace.WriteString("  Timing: ")
	trace.WriteString(fmt.Sprintf("DNS=%v, Connect=%v", dnsTime, connTime))
	if tlsTime > 0 {
		trace.WriteString(fmt.Sprintf(", TLS=%v", tlsTime))
	}
	trace.WriteString(fmt.Sprintf(", TTFB=%v\n", responseTime))

	LogDebug(trace.String())
}
