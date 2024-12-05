// request.go
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/httpx/common/httpx"
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

type GO403BYPASS struct {
	retryClient      *retryablehttp.Client
	errorHandler     *ErrorHandler
	dialer           *fastdialer.Dialer
	config           *Config
	bypassMode       string
	ComparisonLogger []URLParsingLog
}

var gLogFile *os.File

type URLParsingLog struct {
	BypassMode   string `json:"bypass_mode"`
	Canary       string `json:"canary"`
	RawUrlParser struct {
		FullURL    string `json:"full_url"`
		RequestURI string `json:"request_uri"`
	} `json:"raw_parser"`
	UtilParser struct {
		FullURL    string `json:"full_url"`
		RequestURI string `json:"request_uri"`
	} `json:"util_parser"`
	FinalRequest struct {
		FullURL    string `json:"full_url"`
		RequestURI string `json:"request_uri"`
	} `json:"final_request"`
}

type RawLoggingRoundTripper struct {
	wrapped http.RoundTripper
}

// Define custom context key type
type contextKey string

// Define the bypass key constant
const bypassKey contextKey = "bypass"

func (b *GO403BYPASS) printURLParsingLog(log URLParsingLog) {
	LogGreen("\n[PrintAllLogs] [URL Parsing Comparison] [%s] [Canary: %s]\n"+
		"--------------- RawURLParser ---------------\n"+
		"Full URL: %v\n"+
		"Request URI: %v\n"+
		"--------------- URLUtil Parser -------------\n"+
		"Full URL: %v\n"+
		"Request URI: %v\n"+
		"--------------- Final Request --------------\n"+
		"Full URL: %v\n"+
		"Request URI: %v\n"+
		"========================================\n",
		log.BypassMode,
		log.Canary,
		log.RawUrlParser.FullURL,
		log.RawUrlParser.RequestURI,
		log.UtilParser.FullURL,
		log.UtilParser.RequestURI,
		log.FinalRequest.FullURL,
		log.FinalRequest.RequestURI)
}

func (b *GO403BYPASS) PrintAllLogs() {
	for _, log := range b.ComparisonLogger {
		b.printURLParsingLog(log)
	}
}

func (rt *RawLoggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	reqClone := req.Clone(req.Context())

	// Get the raw request bytes BEFORE any modifications by other middleware
	rawReq, err := httputil.DumpRequestOut(reqClone, true)
	if err == nil {
		LogDebug("[RAW-REQUEST-WIRE] >>>\n%s\n<<<", string(rawReq))
	}

	// Perform the actual request
	resp, err := rt.wrapped.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// // Get the raw response bytes BEFORE any processing
	// rawResp, err := httputil.DumpResponse(resp, true)
	// if err == nil {
	// 	LogDebug("[RAW-RESPONSE-WIRE] >>>\n%s\n<<<", string(rawResp))
	// }

	// Capture the final request details
	finalReq, err := httputil.DumpRequestOut(req, true)
	if err == nil {
		relPath := getPathFromRaw(finalReq)
		urlParsingLog := URLParsingLog{
			FinalRequest: struct {
				FullURL    string `json:"full_url"`
				RequestURI string `json:"request_uri"`
			}{
				FullURL:    req.URL.String(),
				RequestURI: relPath,
			},
		}
		LogDebug("[FINAL-REQUEST] >>>\n%s\n<<<", string(finalReq))

		// Update this line to use bypassKey instead of "bypass"
		if bypass, ok := req.Context().Value(bypassKey).(*GO403BYPASS); ok {
			bypass.ComparisonLogger = append(bypass.ComparisonLogger, urlParsingLog)
		}
	}

	return resp, err
}

// New creates a new GO403BYPASS instance
func New(cfg *Config, bypassMode string) (*GO403BYPASS, error) {
	client := &GO403BYPASS{
		config:       cfg,
		bypassMode:   bypassMode,
		errorHandler: NewErrorHandler(), // Initialize here
	}

	// Initialize log file if debug file logging is enabled
	if cfg.Debug && cfg.LogDebugToFile {
		logsDir := "requestslog"
		if err := os.MkdirAll(logsDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create requestslog directory: %v", err)
		}

		// Use Unix timestamp for unique filenames
		filename := fmt.Sprintf("%s/debugrequestslog_%s_%s_%d.jsonl",
			logsDir,
			bypassMode,
			time.Now().Format("20060102_150405"), // YYYYMMDD_HHMMSS
			time.Now().Unix())

		logFile, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %v", err)
		}
		gLogFile = logFile
	}

	// Initialize fastdialer
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
		DialerTimeout:   time.Duration(cfg.Timeout) * time.Second,
		DialerKeepAlive: 10 * time.Second,

		// Cache settings
		CacheMemoryMaxItems: 200,
		WithDialerHistory:   true,
		WithCleanup:         true,

		// TLS settings
		WithZTLS:            false,
		DisableZtlsFallback: false,

		// Fallback settings
		EnableFallback: true,

		// Error handling
		MaxTemporaryErrors:              30,
		MaxTemporaryToPermanentDuration: 1 * time.Minute,
	}

	//LogDebug("[Debug] Starting fastdialer initialization with options: %+v", fastdialerOpts)

	var err error
	client.dialer, err = fastdialer.NewDialer(fastdialerOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create dialer: %v", err)
	}

	if client.dialer == nil {
		return nil, fmt.Errorf("dialer initialization returned nil")
	}

	// Create transport with our dialer
	transport := &http.Transport{
		DialContext: client.dialer.Dial,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return client.dialer.DialTLS(ctx, network, addr)
		},
		MaxIdleConnsPerHost: -1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
		DisableKeepAlives: true,
	}

	// Add proxy if configured
	if cfg.ParsedProxy != nil {
		transport.Proxy = http.ProxyURL(cfg.ParsedProxy)
	}

	// Disable HTTP/2 if not forced
	if !cfg.ForceHTTP2 {
		os.Setenv("GODEBUG", "http2client=0")
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}

	// Wrap the transport with our raw logging round tripper
	rawLoggingTransport := &RawLoggingRoundTripper{
		wrapped: transport,
	}

	// Create retryablehttp client with the wrapped transport
	retryOpts := retryablehttp.Options{
		RetryWaitMin: 1 * time.Second,
		RetryWaitMax: 30 * time.Second,
		RetryMax:     5,
		Timeout:      time.Duration(cfg.Timeout) * time.Second,
		KillIdleConn: true,
		HttpClient: &http.Client{
			Transport: rawLoggingTransport, // Use our wrapped transport here
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

// NewRawRequestFromURLWithContext creates a request with optional tracing while preserving raw paths
func (b *GO403BYPASS) NewRawRequestFromURLWithContext(ctx context.Context, method, targetURL string) (*retryablehttp.Request, error) {
	ctx = context.WithValue(ctx, bypassKey, b)

	// Parse URL using urlutil with unsafe mode to preserve raw paths
	urlx, err := urlutil.ParseURL(targetURL, true)
	if err != nil {
		return nil, err
	}

	// Create request using retryablehttp
	req, err := retryablehttp.NewRequestFromURLWithContext(ctx, method, urlx, nil)
	if err != nil {
		return nil, err
	}

	// Log the URL parsing
	urlParsingLog := URLParsingLog{}
	urlParsingLog.UtilParser.FullURL = fmt.Sprintf("%s://%s%s%s", urlx.URL.Scheme, urlx.URL.Host, urlx.URL.Path, urlx.Params.Encode())
	urlParsingLog.UtilParser.RequestURI = req.URL.URL.RequestURI()

	// Append the log to the GO403BYPASS instance
	b.ComparisonLogger = append(b.ComparisonLogger, urlParsingLog)

	return req, nil
}

// NewRawRequestFromURL is a convenience wrapper around NewRawRequestFromURLWithContext
func (b *GO403BYPASS) NewRawRequestFromURL(method, targetURL string) (*retryablehttp.Request, error) {
	return b.NewRawRequestFromURLWithContext(context.Background(), method, targetURL)
}

// sendRequest sends an HTTP request using retryablehttp
func (b *GO403BYPASS) sendRequest(method, rawURL string, headers []Header) (*ResponseDetails, error) {
	// First parse with rawurlparser to preserve exact format
	parsedURL, err := rawurlparser.RawURLParse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL %s: %v", rawURL, err)
	}

	rawURLString := fmt.Sprintf("%s://%s%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path, parsedURL.Query)
	canary := generateRandomString(18)

	// Create request
	req, err := b.NewRawRequestFromURL(method, rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Log both parsed URLs in a single block
	if b.config.Debug {

		// Log the raw URL parsing
		urlParsingLog := URLParsingLog{
			BypassMode: b.bypassMode,
			Canary:     canary,
		}
		urlParsingLog.RawUrlParser.FullURL = rawURLString
		urlParsingLog.RawUrlParser.RequestURI = fmt.Sprintf("%s%s", parsedURL.Path, parsedURL.Query)

		b.ComparisonLogger = append(b.ComparisonLogger, urlParsingLog)

		urlutilString := fmt.Sprintf("%s://%s%s%s", req.URL.Scheme, req.URL.Host, req.URL.Path, req.URL.RawQuery)
		urlParsingLog.UtilParser.FullURL = urlutilString
		urlParsingLog.UtilParser.RequestURI = req.URL.RequestURI()

		LogGreen("\n[URL Parsing Comparison] [%s] [Canary: %s]\n"+
			"--------------- RawURLParser ---------------\n"+
			"Full URL: %s\n"+
			"Request URI: %s\n",
			b.bypassMode,
			canary,
			rawURLString,
			fmt.Sprintf("%s%s", parsedURL.Path, parsedURL.Query))
		LogPink("--------------- URLUtil Parser -------------\n"+
			"Full URL: %s\n"+
			"Request URI: %s\n"+
			"========================================\n",
			urlutilString,
			req.URL.URL.RequestURI())
	}

	if !containsHeader(headers, "User-Agent") {
		req.Header.Set("User-Agent", defaultUserAgent)
	}

	// Debug canary
	if b.config.Debug {
		//canary := generateRandomString(18)
		req.Header.Set("X-Go-Bypass-403", canary)
		// LogDebug("[sendRequest] [%s] [Canary: %s] Sending request: %s [Headers: %s]\n",
		// 	b.bypassMode,
		// 	canary,
		// 	rawURLString,
		// 	formatHeaders(headers))
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
	if !validateStatusCode(b.config.MatchStatusCodes, resp.StatusCode) {
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

	// // Debug logging
	// if b.config.Verbose {
	// 	LogYellow("=====> Response Details for URL %s\n", rawURLString)
	// 	LogYellow("Status: %d %s\n", resp.StatusCode, resp.Status)
	// 	LogYellow("Headers:\n%s\n", details.ResponseHeaders)
	// 	LogYellow("Body (%d bytes):\n%s\n", details.ResponseBytes, details.ResponsePreview)
	// 	LogYellow("=====> End of Response Details\n")
	// }

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

func validateStatusCode(codes []int, code int) bool {
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

// func (b *GO403BYPASS) validateRequest(req *retryablehttp.Request) error {
// 	// Verify URL structure preservation
// 	// Check header ordering if critical
// 	// Validate any bypass-specific requirements
// 	return nil
// }

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

func getPathFromRaw(bin []byte) (relpath string) {
	buff := bufio.NewReader(bytes.NewReader(bin))
readline:
	line, err := buff.ReadString('\n')
	if err != nil {
		return
	}
	if strings.Contains(line, "HTTP/1.1") {
		parts := strings.Split(line, " ")
		if len(parts) == 3 {
			relpath = parts[1]
			return
		}
	}
	goto readline
}
