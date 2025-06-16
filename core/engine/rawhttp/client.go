/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package rawhttp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
	GB403ErrorHandler "github.com/slicingmelon/gobypass403/core/utils/error"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
	"github.com/valyala/fasthttp"
)

var (
	CustomUserAgent = []byte("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
)

var (
	ErrReqFailedMaxRetries          = errors.New("request failed after all retry attempts")
	ErrReqFailedMaxConsecutiveFails = errors.New("target reached max consecutive fails")
)

// Constants for buffer sizes used throughout the package
const (
	DefaultHeadersBuffSize = 8192
	DefaultBufferPadding   = 1024
)

// ParsedHeader represents a pre-processed custom header
type ParsedHeader struct {
	Name  string
	Value string
}

// HTTPClientOptions contains configuration options for the HTTPClient
type HTTPClientOptions struct {
	BypassModule             string        // ScannerCliOpts
	Timeout                  time.Duration // ScannerCliOpts
	DialTimeout              time.Duration // Custom Dial Timeout
	MaxConnsPerHost          int           // fasthttp core
	MaxIdleConnDuration      time.Duration // fasthttp core
	MaxConnWaitTimeout       time.Duration // fasthttp core
	NoDefaultUserAgent       bool          // fasthttp core
	ProxyURL                 string        // ScannerCliOpts
	MaxResponseBodySize      int           // fasthttp core
	ReadBufferSize           int           // fasthttp core
	WriteBufferSize          int           // fasthttp core
	MaxRetries               int           // ScannerCliOpts
	ResponseBodyPreviewSize  int           // ScannerCliOpts
	StreamResponseBody       bool          // fasthttp core
	MatchStatusCodes         []int         // ScannerCliOpts
	DisableKeepAlive         bool
	EnableHTTP2              bool
	Dialer                   fasthttp.DialFunc
	RequestDelay             time.Duration // ScannerCliOpts
	RetryDelay               time.Duration // ScannerCliOpts
	MaxConsecutiveFailedReqs int           // ScannerCliOpts
	AutoThrottle             bool          // ScannerCliOpts
	DisablePathNormalizing   bool
	CustomHTTPHeaders        []string        // Raw header strings from CLI
	ParsedHeaders            []ParsedHeader  // Pre-processed headers for fast access
	HeaderOverrides          map[string]bool // Track which headers are overridden by CLI (lowercase keys)
}

// HTTPClient represents a reusable HTTP client
type HTTPClient struct {
	client                *fasthttp.Client
	options               *HTTPClientOptions
	retryConfig           *RetryConfig
	throttler             *Throttler
	mu                    sync.RWMutex
	lastResponseTime      atomic.Int64
	consecutiveFailedReqs atomic.Int32
}

// DefaultHTTPClientOptions returns the default HTTP client options
func DefaultHTTPClientOptions() *HTTPClientOptions {
	// Default response preview size (if not specified by user)
	defaultPreviewSize := 1024

	// Calculate default max body size based on headers + preview + margin
	maxBodySize := DefaultHeadersBuffSize + defaultPreviewSize + DefaultBufferPadding

	// Calculate RW buffer size with additional margin
	rwBufferSize := maxBodySize + DefaultBufferPadding

	return &HTTPClientOptions{
		BypassModule:             "",
		Timeout:                  20000 * time.Millisecond,
		DialTimeout:              5 * time.Second,
		MaxConnsPerHost:          128,
		MaxIdleConnDuration:      1 * time.Minute,
		MaxConnWaitTimeout:       1 * time.Second,
		NoDefaultUserAgent:       true,
		MaxResponseBodySize:      maxBodySize,
		ReadBufferSize:           rwBufferSize,
		WriteBufferSize:          rwBufferSize,
		StreamResponseBody:       true,
		ResponseBodyPreviewSize:  defaultPreviewSize,
		MaxRetries:               2,
		RetryDelay:               500 * time.Millisecond,
		RequestDelay:             0,
		AutoThrottle:             false,
		DisableKeepAlive:         false,
		DisablePathNormalizing:   true,
		Dialer:                   nil,
		MaxConsecutiveFailedReqs: 15,
	}
}

// NewHTTPClient creates a new HTTP client instance
func NewHTTPClient(opts *HTTPClientOptions) *HTTPClient {
	if opts == nil {
		opts = DefaultHTTPClientOptions()
	}

	// Preprocess custom headers for fast access in hot path
	opts.PreprocessCustomHeaders()

	// Calculate appropriate sizes based on preview size
	previewSize := opts.ResponseBodyPreviewSize
	if previewSize <= 0 {
		previewSize = 1024 // Default if not specified
	}

	// Ensure MaxResponseBodySize is large enough for headers + preview
	requiredBodySize := DefaultHeadersBuffSize + previewSize + DefaultBufferPadding
	if opts.MaxResponseBodySize < requiredBodySize {
		opts.MaxResponseBodySize = requiredBodySize
	}

	// Ensure read/write buffers are sized appropriately
	requiredBufferSize := opts.MaxResponseBodySize + DefaultBufferPadding
	if opts.ReadBufferSize <= 0 || opts.ReadBufferSize < requiredBufferSize {
		opts.ReadBufferSize = requiredBufferSize
	}
	if opts.WriteBufferSize <= 0 || opts.WriteBufferSize < requiredBufferSize {
		opts.WriteBufferSize = requiredBufferSize
	}

	// Continue with existing initialization...
	if opts.Dialer == nil {
		opts.Dialer = CreateHTTPClientDialer(opts.DialTimeout, opts.ProxyURL)
	}

	retryConfig := DefaultRetryConfig()
	retryConfig.MaxRetries = opts.MaxRetries
	retryConfig.RetryDelay = opts.RetryDelay

	var throttler *Throttler
	if opts.AutoThrottle {
		throttler = NewThrottler(DefaultThrottleConfig())
	}

	c := &HTTPClient{
		options:     opts,
		retryConfig: retryConfig,
		throttler:   throttler,
	}

	// reset failed consecutive requests
	c.ResetConsecutiveFailedReqs()

	client := &fasthttp.Client{
		MaxConnsPerHost:               opts.MaxConnsPerHost,
		MaxIdleConnDuration:           opts.MaxIdleConnDuration,
		MaxConnWaitTimeout:            opts.MaxConnWaitTimeout,
		DisableHeaderNamesNormalizing: true,
		DisablePathNormalizing:        opts.DisablePathNormalizing,
		NoDefaultUserAgentHeader:      true,
		MaxResponseBodySize:           opts.MaxResponseBodySize,
		ReadBufferSize:                opts.ReadBufferSize,
		WriteBufferSize:               opts.WriteBufferSize,
		ReadTimeout:                   opts.Timeout,
		WriteTimeout:                  opts.Timeout,
		StreamResponseBody:            opts.StreamResponseBody,
		Dial:                          opts.Dialer,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
			Renegotiation:      tls.RenegotiateOnceAsClient,
			ClientSessionCache: tls.NewLRUClientSessionCache(1024),
		},
	}

	c.client = client
	return c
}

// NewHTTPClientWith creates a client with default options plus custom settings
func NewDefaultHTTPClient(httpClientOpts *HTTPClientOptions) *HTTPClient {
	// Get default options
	opts := DefaultHTTPClientOptions()

	// If custom options provided, copy them to the default options
	if httpClientOpts != nil {
		// Handle boolean values explicitly since they're zero by default
		if httpClientOpts.DisableKeepAlive {
			opts.DisableKeepAlive = true
		}
		if httpClientOpts.NoDefaultUserAgent {
			opts.NoDefaultUserAgent = true
		}
		if httpClientOpts.AutoThrottle {
			opts.AutoThrottle = true
		}
		if httpClientOpts.EnableHTTP2 {
			opts.EnableHTTP2 = true
		}
		if httpClientOpts.DisablePathNormalizing {
			opts.DisablePathNormalizing = true
		}
		if httpClientOpts.StreamResponseBody {
			opts.StreamResponseBody = true
		}

		// Handle non-boolean fields only if they're non-zero values
		if httpClientOpts.Timeout != 0 {
			opts.Timeout = httpClientOpts.Timeout
		}
		if httpClientOpts.DialTimeout != 0 {
			opts.DialTimeout = httpClientOpts.DialTimeout
		}
		if httpClientOpts.MaxConnsPerHost != 0 {
			opts.MaxConnsPerHost = httpClientOpts.MaxConnsPerHost
		}
		if httpClientOpts.MaxRetries != 0 {
			opts.MaxRetries = httpClientOpts.MaxRetries
		}
		if httpClientOpts.ProxyURL != "" {
			opts.ProxyURL = httpClientOpts.ProxyURL
		}
		if httpClientOpts.BypassModule != "" {
			opts.BypassModule = httpClientOpts.BypassModule
		}
		if httpClientOpts.Dialer != nil {
			opts.Dialer = httpClientOpts.Dialer
		}
		if len(httpClientOpts.MatchStatusCodes) > 0 {
			opts.MatchStatusCodes = httpClientOpts.MatchStatusCodes
		}
		if httpClientOpts.RequestDelay > 0 {
			opts.RequestDelay = httpClientOpts.RequestDelay
		}
		if httpClientOpts.RetryDelay > 0 {
			opts.RetryDelay = httpClientOpts.RetryDelay
		}
		if httpClientOpts.MaxConsecutiveFailedReqs > 0 {
			opts.MaxConsecutiveFailedReqs = httpClientOpts.MaxConsecutiveFailedReqs
		}
		if len(httpClientOpts.CustomHTTPHeaders) > 0 {
			opts.CustomHTTPHeaders = httpClientOpts.CustomHTTPHeaders
		}

		// Handle ResponseBodyPreviewSize and associated buffer sizes
		if httpClientOpts.ResponseBodyPreviewSize > 0 {
			opts.ResponseBodyPreviewSize = httpClientOpts.ResponseBodyPreviewSize
		}

		// Apply max response body size if explicitly set
		if httpClientOpts.MaxResponseBodySize > 0 {
			opts.MaxResponseBodySize = httpClientOpts.MaxResponseBodySize
		}

		// Apply read/write buffer sizes if explicitly set
		if httpClientOpts.ReadBufferSize > 0 {
			opts.ReadBufferSize = httpClientOpts.ReadBufferSize
		}

		if httpClientOpts.WriteBufferSize > 0 {
			opts.WriteBufferSize = httpClientOpts.WriteBufferSize
		}
	}

	return NewHTTPClient(opts)
}

func (c *HTTPClient) GetHTTPClientOptions() *HTTPClientOptions {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.options
}

// SetDialer sets a custom dialer for the client
func (c *HTTPClient) SetDialer(dialer fasthttp.DialFunc) *HTTPClient {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.client != nil {
		c.client.Dial = dialer
	}
	return c
}

func (c *HTTPClient) handleRetries(req *fasthttp.Request, resp *fasthttp.Response, bypassPayload payload.BypassPayload, retryAction RetryAction) (int64, error) {
	c.retryConfig.ResetPerReqAttempts()

	for attempt := 1; attempt <= c.retryConfig.MaxRetries; attempt++ {
		// Apply retry delay
		time.Sleep(c.retryConfig.RetryDelay)

		// Prepare request copy for retry
		reqCopy := fasthttp.AcquireRequest()
		ReqCopyToWithSettings(req, reqCopy)
		defer fasthttp.ReleaseRequest(reqCopy)

		if c.throttler != nil && c.throttler.IsThrottlerActive() {
			c.throttler.ThrottleRequest()
		}

		var start time.Time
		var err error

		switch retryAction {
		case RetryWithConnectionClose:
			reqCopy.Header.Del("Connection")
			reqCopy.SetConnectionClose()
			start = time.Now()
			err = c.client.Do(reqCopy, resp)

		case RetryWithoutResponseStreaming:
			noStreamOpts := c.GetHTTPClientOptions()
			noStreamOpts.StreamResponseBody = false
			tempClient := NewHTTPClient(noStreamOpts)
			reqCopy.SetConnectionClose()
			start = time.Now()
			err = tempClient.client.Do(reqCopy, resp)

		default:
			start = time.Now()
			err = c.client.Do(reqCopy, resp)
		}

		requestTime := time.Since(start)

		if err != nil {
			errCtx := GB403ErrorHandler.ErrorContext{
				ErrorSource:  fmt.Sprintf("handleRetries/Retry-%d", attempt),
				Host:         payload.BypassPayloadToBaseURL(bypassPayload),
				BypassModule: bypassPayload.BypassModule,
				DebugToken:   bypassPayload.PayloadToken,
			}

			// Handle error but continue if whitelisted
			if err = GB403ErrorHandler.GetErrorHandler().HandleErrorAndContinue(err, errCtx); err == nil {
				return requestTime.Milliseconds(), nil
			}

			c.retryConfig.PerReqRetriedAttempts.Add(1)
			resp.Reset()
			continue
		}

		// Handle successful response
		if c.throttler.IsThrottableRespCode(resp.StatusCode()) {
			c.throttler.EnableThrottler()
		}

		return requestTime.Milliseconds(), nil
	}

	return 0, ErrReqFailedMaxRetries
}

/*
// DoRequest performs a HTTP request (raw)
// Returns the HTTP response time (in ms) and error

To remember!
ErrNoFreeConns is returned when no free connections available
to the given host.

Increase the allowed number of connections per host if you
see this error.

ErrNoFreeConns ErrConnectionClosed may be returned from client methods if the server
closes connection before returning the first response byte.

If you see this error, then either fix the server by returning
'Connection: close' response header before closing the connection
or add 'Connection: close' request header before sending requests
to broken server.
*/
func (c *HTTPClient) DoRequest(req *fasthttp.Request, resp *fasthttp.Response, bypassPayload payload.BypassPayload) (int64, error) {

	if c.GetHTTPClientOptions().RequestDelay > 0 {
		time.Sleep(c.GetHTTPClientOptions().RequestDelay)
	}
	// apply throttler if enabled
	if c.throttler.IsThrottlerActive() {
		c.throttler.ThrottleRequest()
	}

	// Initial request
	start := time.Now()
	err := c.client.Do(req, resp)
	requestTime := time.Since(start)

	// Handle initial request result
	if err != nil {
		errCtx := GB403ErrorHandler.ErrorContext{
			ErrorSource:  "DoRequest",
			Host:         payload.BypassPayloadToBaseURL(bypassPayload),
			BypassModule: bypassPayload.BypassModule,
			DebugToken:   bypassPayload.PayloadToken,
		}

		// Handle error but continue if whitelisted
		if err = GB403ErrorHandler.GetErrorHandler().HandleErrorAndContinue(err, errCtx); err == nil {
			return requestTime.Milliseconds(), nil
		}

		// Check if we should retry
		retryDecision := IsRetryableError(err)
		if !retryDecision.ShouldRetry {
			return requestTime.Milliseconds(), err
		}

		// Attempt retries
		retryTime, retryErr := c.handleRetries(req, resp, bypassPayload, retryDecision.Action)
		if retryErr != nil {
			if errors.Is(retryErr, ErrReqFailedMaxRetries) {
				newCount := c.consecutiveFailedReqs.Add(1)
				GB403Logger.Debug().Msgf("Consecutive failures for %s: %d/%d (error: %v)\n",
					bypassPayload.BypassModule, newCount, c.options.MaxConsecutiveFailedReqs, err)
				if newCount >= int32(c.options.MaxConsecutiveFailedReqs) {
					//GB403Logger.Warning().Msgf("Max consecutive failures reached for %s: %d/%d -- Cancelling current bypass module\n",
					//	bypassPayload.BypassModule, newCount, c.options.MaxConsecutiveFailedReqs)
					return retryTime, ErrReqFailedMaxConsecutiveFails
				}
			}
			return retryTime, fmt.Errorf("request failed after %d retries: %w",
				c.retryConfig.GetPerReqRetriedAttempts(), retryErr)
		}
		return retryTime, nil
	}

	// Handle successful response
	if c.throttler.IsThrottableRespCode(resp.StatusCode()) {
		c.throttler.EnableThrottler()
	}

	return requestTime.Milliseconds(), nil
}

func (c *HTTPClient) GetPerReqRetryAttempts() int32 {
	return c.retryConfig.GetPerReqRetriedAttempts()
}

func (c *HTTPClient) ResetConsecutiveFailedReqs() {
	c.consecutiveFailedReqs.Store(0)
}

func (c *HTTPClient) GetConsecutiveFailures() int32 {
	return c.consecutiveFailedReqs.Load()
}

// GetLastResponseTime returns the last HTTP response time in milliseconds
func (c *HTTPClient) GetLastResponseTime() int64 {
	return c.lastResponseTime.Load()
}

// IsThrottlerActive returns true if the throttler is currently active
func (c *HTTPClient) IsThrottlerActive() bool {
	return c.throttler.IsThrottlerActive()
}

// DisableThrottler disables the throttler, it does not reset the stats and rates though.
func (c *HTTPClient) DisableThrottler() {
	c.throttler.DisableThrottler()
}

func (c *HTTPClient) GetThrottler() *Throttler {
	return c.throttler
}

func (c *HTTPClient) DisableStreamResponseBody() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.client.StreamResponseBody = false
}

func (c *HTTPClient) EnableStreamResponseBody() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.client.StreamResponseBody = true
}

// Close releases all idle connections
func (c *HTTPClient) Close() {
	c.client.CloseIdleConnections()
	c.throttler.ResetThrottler()
}

// // DoRawHAProxyRequest sends a raw HAProxy exploit request, carefully preserving header order
// // The raw request is already built and stored in req.Body()
// func (c *HTTPClient) DoRawHAProxyRequest(req *fasthttp.Request, resp *fasthttp.Response, bypassPayload payload.BypassPayload) (int64, error) {
// 	// Extract necessary connection details directly from the bypassPayload
// 	scheme := bypassPayload.Scheme
// 	host := bypassPayload.Host
// 	if scheme == "" {
// 		scheme = "http" // Default to HTTP if not specified
// 	}

// 	// Create a TCP connection directly
// 	dialFunc := c.client.Dial
// 	if dialFunc == nil {
// 		dialFunc = fasthttp.Dial // Use default if not set
// 	}

// 	// Connect to the target
// 	start := time.Now()
// 	conn, err := dialFunc(scheme + "://" + host)
// 	if err != nil {
// 		return 0, fmt.Errorf("error connecting to HAProxy target %s: %w", host, err)
// 	}
// 	defer conn.Close()

// 	// Our raw request is already constructed and in the body
// 	rawRequest := req.Body()
// 	if len(rawRequest) == 0 {
// 		return 0, fmt.Errorf("empty raw HAProxy request")
// 	}

// 	// Send the raw request exactly as-is
// 	if _, err = conn.Write(rawRequest); err != nil {
// 		return 0, fmt.Errorf("error writing raw HAProxy request: %w", err)
// 	}

// 	// Use a buffer to read the response
// 	bufReader := bufio.NewReader(conn)

// 	// Parse the response directly
// 	if err = resp.Read(bufReader); err != nil {
// 		return 0, fmt.Errorf("error reading HAProxy response: %w", err)
// 	}

// 	// Calculate request time
// 	requestTime := time.Since(start)

// 	return requestTime.Milliseconds(), nil
// }

// PreprocessCustomHeaders parses raw CLI header strings into optimized format
func (opts *HTTPClientOptions) PreprocessCustomHeaders() {
	if len(opts.CustomHTTPHeaders) == 0 {
		return
	}

	opts.ParsedHeaders = make([]ParsedHeader, 0, len(opts.CustomHTTPHeaders))
	opts.HeaderOverrides = make(map[string]bool, len(opts.CustomHTTPHeaders))

	for _, header := range opts.CustomHTTPHeaders {
		colonIdx := strings.Index(header, ":")
		if colonIdx == -1 {
			continue // Skip invalid headers
		}

		name := strings.TrimSpace(header[:colonIdx])
		value := strings.TrimSpace(header[colonIdx+1:])

		if name == "" {
			continue // Skip empty header names
		}

		opts.ParsedHeaders = append(opts.ParsedHeaders, ParsedHeader{
			Name:  name,
			Value: value,
		})

		// Track header override using lowercase for case-insensitive lookup
		opts.HeaderOverrides[strings.ToLower(name)] = true
	}
}
