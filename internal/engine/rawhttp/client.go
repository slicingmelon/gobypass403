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
	const (
		maxBodySize  = 12288 //
		rwBufferSize = maxBodySize + 4096
	)

	return &HTTPClientOptions{
		BypassModule:             "",
		Timeout:                  20000 * time.Millisecond,
		DialTimeout:              5 * time.Second,
		MaxConnsPerHost:          128,
		MaxIdleConnDuration:      1 * time.Minute, // Idle keep-alive connections are closed after this duration.
		MaxConnWaitTimeout:       1 * time.Second, // Maximum duration for waiting for a free connection.
		NoDefaultUserAgent:       true,
		MaxResponseBodySize:      maxBodySize,  //
		ReadBufferSize:           rwBufferSize, //
		WriteBufferSize:          rwBufferSize, //
		StreamResponseBody:       true,
		MaxRetries:               2,
		RetryDelay:               500 * time.Millisecond,
		RequestDelay:             0,
		AutoThrottle:             false,
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
			//ClientSessionCache:     tls.NewLRUClientSessionCache(1024), // Session cache to resume sessions
			//SessionTicketsDisabled: true,
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
			//tempClient.client.CloseIdleConnections()

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
