package rawhttp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	"github.com/valyala/fasthttp"
)

var (
	CustomUserAgent = []byte("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
)

var (
	ErrReqFailedMaxRetries          = errors.New("request failed after all retry attempts")
	ErrReqFailedMaxConsecutiveFails = errors.New("target reached max consecutive fails")
)

// HTTPClientOptions contains configuration options for the HTTPClient
type HTTPClientOptions struct {
	BypassModule        string        // ScannerCliOpts
	Timeout             time.Duration // ScannerCliOpts
	DialTimeout         time.Duration // Custom Dial Timeout
	MaxConnsPerHost     int           // fasthttp core
	MaxIdleConnDuration time.Duration // fasthttp core
	MaxConnWaitTimeout  time.Duration // fasthttp core
	NoDefaultUserAgent  bool          // fasthttp core
	ProxyURL            string        // ScannerCliOpts
	MaxResponseBodySize int           // fasthttp core
	//ReadBufferSize           int           // fasthttp core
	//WriteBufferSize          int           // fasthttp core
	MaxRetries               int           // ScannerCliOpts
	ResponseBodyPreviewSize  int           // ScannerCliOpts
	StreamResponseBody       bool          // fasthttp core
	MatchStatusCodes         []int         // ScannerCliOpts
	RetryDelay               time.Duration // ScannerCliOpts
	DisableKeepAlive         bool
	EnableHTTP2              bool
	Dialer                   fasthttp.DialFunc
	RequestDelay             time.Duration // ScannerCliOpts
	MaxConsecutiveFailedReqs int           // ScannerCliOpts
	DisablePathNormalizing   bool
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
	// const (
	// 	KB              = 1024
	// 	headerAllowance = 5 * KB  // 5120 bytes for headers (based on github.com.. huge list of headers)
	// 	maxBodySize     = 12 * KB // 12288 bytes for body
	// 	bufferSize      = 18 * KB // 18432 bytes (headers + body + some padding)
	// )

	return &HTTPClientOptions{
		BypassModule:        "",
		Timeout:             20000 * time.Millisecond,
		DialTimeout:         5 * time.Second,
		MaxConnsPerHost:     128,
		MaxIdleConnDuration: 1 * time.Minute, // Idle keep-alive connections are closed after this duration.
		MaxConnWaitTimeout:  1 * time.Second, // Maximum duration for waiting for a free connection.
		NoDefaultUserAgent:  true,
		MaxResponseBodySize: 12 * 1024, // 12288 bytes - just body limit
		//ReadBufferSize:           bufferSize,  // 18432 bytes - total buffer
		//WriteBufferSize:          bufferSize,  // 18432 bytes - total buffer
		StreamResponseBody:       true,
		MaxRetries:               2,
		RetryDelay:               500 * time.Millisecond,
		RequestDelay:             0,
		DisableKeepAlive:         false, // Keep connections alive
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

	// Set the default dialer if none is provided
	if opts.Dialer == nil {
		opts.Dialer = CreateDialFunc(opts)
	}

	retryConfig := DefaultRetryConfig()
	retryConfig.MaxRetries = opts.MaxRetries
	retryConfig.RetryDelay = opts.RetryDelay

	c := &HTTPClient{
		options:     opts,
		retryConfig: retryConfig,
		throttler:   NewThrottler(DefaultThrottleConfig()),
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
		//ReadBufferSize:                opts.ReadBufferSize,
		//WriteBufferSize:               opts.WriteBufferSize,
		StreamResponseBody: opts.StreamResponseBody,
		Dial:               opts.Dialer,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
			ClientSessionCache: tls.NewLRUClientSessionCache(1024), // Session cache to resume sessions
		},
	}

	c.client = client
	return c
}

func (c *HTTPClient) GetHTTPClientOptions() *HTTPClientOptions {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.options
}

// SetHTTPClientOptions updates the client options with a copy
func (c *HTTPClient) SetHTTPClientOptions(opts *HTTPClientOptions) {
	c.mu.Lock()
	defer c.mu.Unlock()

	newOpts := *opts
	c.options = &newOpts
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

		var start time.Time
		var err error

		switch retryAction {
		case RetryWithConnectionClose:
			reqCopy.Header.Del("Connection")
			reqCopy.SetConnectionClose()
			start = time.Now()
			err = c.client.DoTimeout(reqCopy, resp, c.options.Timeout)

		case RetryWithoutResponseStreaming:
			noStreamOpts := c.GetHTTPClientOptions()
			noStreamOpts.StreamResponseBody = false
			tempClient := NewHTTPClient(noStreamOpts)
			reqCopy.SetConnectionClose()
			start = time.Now()
			err = tempClient.client.DoTimeout(reqCopy, resp, c.options.Timeout)
			tempClient.client.CloseIdleConnections()

		default:
			start = time.Now()
			err = c.client.DoTimeout(reqCopy, resp, c.options.Timeout)
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

// DoRequest performs a HTTP request (raw)
// Returns the HTTP response time (in ms) and error
func (c *HTTPClient) DoRequest(req *fasthttp.Request, resp *fasthttp.Response, bypassPayload payload.BypassPayload) (int64, error) {
	// Initial request
	start := time.Now()
	err := c.client.DoTimeout(req, resp, c.options.Timeout)
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
			if retryErr == ErrReqFailedMaxRetries {
				newCount := c.consecutiveFailedReqs.Add(1)
				if newCount >= int32(c.options.MaxConsecutiveFailedReqs) {
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

// AcquireRequest returns a new Request instance from pool
func (c *HTTPClient) AcquireRequest() *fasthttp.Request {
	return fasthttp.AcquireRequest()
}

// ReleaseRequest returns request to pool
func (c *HTTPClient) ReleaseRequest(req *fasthttp.Request) {
	fasthttp.ReleaseRequest(req)
}

// AcquireResponse returns a new Response instance from pool
func (c *HTTPClient) AcquireResponse() *fasthttp.Response {
	return fasthttp.AcquireResponse()
}

// ReleaseResponse returns response to pool
func (c *HTTPClient) ReleaseResponse(resp *fasthttp.Response) {
	fasthttp.ReleaseResponse(resp)
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
	originalScheme := src.URI().Scheme() // Returns []byte
	originalHost := src.URI().Host()     // Returns []byte

	//GB403Logger.Debug().Msgf("Original values - scheme=%s host=%s",
	//	originalScheme, originalHost) // Use bytes directly in logging

	// Use byte variants to avoid allocations
	dst.URI().SetSchemeBytes(originalScheme)
	dst.URI().SetHostBytes(originalHost)

	// Check if Host header exists using case-insensitive lookup
	hostKey := []byte("Host")
	if len(PeekRequestHeaderKeyCaseInsensitive(dst, hostKey)) == 0 {
		//GB403Logger.Debug().Msgf("No Host header found, setting from URI.Host: %s", originalHost)
		dst.Header.SetHostBytes(originalHost)
	}

	// GB403Logger.Debug().Msgf("After SetScheme/SetHost - scheme=%s host=%s header_host=%s",
	// 	dst.URI().Scheme(), dst.URI().Host(),
	// 	PeekRequestHeaderKeyCaseInsensitive(dst, hostKey))

	return dst
}
