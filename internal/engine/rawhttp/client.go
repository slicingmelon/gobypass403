package rawhttp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/tiendc/gofn"
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
	const (
		KB              = 1024
		headerAllowance = 5 * KB  // 5120 bytes for headers (based on github.com.. huge list of headers)
		maxBodySize     = 12 * KB // 12288 bytes for body
		bufferSize      = 18 * KB // 18432 bytes (headers + body + some padding)
	)

	return &HTTPClientOptions{
		BypassModule:             "",
		Timeout:                  20000 * time.Millisecond,
		DialTimeout:              5 * time.Second,
		MaxConnsPerHost:          128,
		MaxIdleConnDuration:      1 * time.Minute, // Idle keep-alive connections are closed after this duration.
		MaxConnWaitTimeout:       1 * time.Second, // Maximum duration for waiting for a free connection.
		NoDefaultUserAgent:       true,
		MaxResponseBodySize:      maxBodySize, // 12288 bytes - just body limit
		ReadBufferSize:           bufferSize,  // 18432 bytes - total buffer
		WriteBufferSize:          bufferSize,  // 18432 bytes - total buffer
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
		ReadBufferSize:                opts.ReadBufferSize,
		WriteBufferSize:               opts.WriteBufferSize,
		StreamResponseBody:            opts.StreamResponseBody,
		//ReadTimeout:                   opts.Timeout,
		//WriteTimeout:                  opts.Timeout,
		Dial: opts.Dialer,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
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

func (c *HTTPClient) execFunc(req *fasthttp.Request, resp *fasthttp.Response, job payload.PayloadJob) (int64, error) {
	c.retryConfig.ResetPerReqAttempts()
	//var lastErr error

	reqCopy := ReqCopyToWithSettings(req)
	defer fasthttp.ReleaseRequest(reqCopy)

	GB403Logger.Debug().Msgf("Request copy details: scheme=%s host=%s path=%s",
		reqCopy.URI().Scheme(), reqCopy.URI().Host(), reqCopy.URI().Path())

	// Capture original timeout and retry delay from the global options and retry config.
	origOpts := c.GetHTTPClientOptions()
	baseTimeout := origOpts.Timeout
	retryDelay := c.retryConfig.RetryDelay
	maxRetries := c.retryConfig.MaxRetries

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Apply the request delay to all requests (from cli opts)
		if origOpts.RequestDelay > 0 {
			time.Sleep(origOpts.RequestDelay)
		}

		// Apply throttler delay if active (only on first attempt)
		if attempt == 0 && c.throttler.IsThrottlerActive() {
			c.throttler.ThrottleRequest()
		}

		// Calculate timeout for this attempt
		currentTimeout := baseTimeout
		if attempt > 0 {
			// For retry attempts:
			// 1. Sleep for retry delay
			//GB403Logger.Debug().Msgf("Sleeping for retry delay: %v\n", retryDelay)
			time.Sleep(retryDelay)

			// 2. Increase timeout based on attempt number
			currentTimeout = baseTimeout + time.Duration(attempt)*retryDelay

			// 3. Disable keep-alive for retries
			//reqCopy.Header.Del("Connection")
			reqCopy.Header.Set("Connection", "close")
		}

		// For retries, re-apply all settings again
		//eqCopy.SetConnectionClose()
		reqCopy.URI().DisablePathNormalizing = true
		reqCopy.Header.DisableNormalizing()
		reqCopy.Header.SetNoDefaultContentType(true)
		reqCopy.UseHostHeader = true
		reqCopy.URI().SetScheme(string(req.URI().Scheme()))
		reqCopy.URI().SetHost(string(req.URI().Host()))

		GB403Logger.Debug().Msgf("Attempt %d: timeout=%v (base=%v)\n", attempt, currentTimeout, baseTimeout)

		start := time.Now()
		err := c.client.DoTimeout(reqCopy, resp, currentTimeout)
		elapsed := time.Since(start)

		if err != nil {
			jobURL := job.Scheme + "://" + job.Host
			reqURL := string(reqCopy.URI().Scheme()) + "://" + string(reqCopy.URI().Host())

			errorContext := GB403ErrorHandler.ErrorContext{
				ErrorSource:  []byte("HTTPClient.execFunc/attempt=" + strconv.Itoa(attempt)),
				Host:         []byte(gofn.FirstNonEmpty(jobURL, reqURL)),
				BypassModule: []byte(job.BypassModule),
				DebugToken:   []byte(job.PayloadToken),
			}
			if handleErr := GB403ErrorHandler.GetErrorHandler().HandleError(err, errorContext); handleErr != nil {
				return 0, fmt.Errorf("error handling failed: %v (original error: %v)", handleErr, err)
			}

			lastErr = err

			retryDecision := IsRetryableError(err)
			if !retryDecision.ShouldRetry {
				GB403Logger.Debug().Msgf("Non-retryable error: %v\n", err)
				return elapsed.Milliseconds(), err
			}

			if attempt < maxRetries {
				switch retryDecision.Action {
				case RetryWithConnectionClose:
					reqCopy.Header.Del("Connection")
					reqCopy.Header.Set("Connection", "close")
				case RetryWithoutResponseStreaming:
					c.DisableStreamResponseBody()
					defer c.EnableStreamResponseBody()
				}
				c.retryConfig.PerReqRetriedAttempts.Add(1)
				resp.Reset()
				continue
			}

			return 0, fmt.Errorf("%w: %v", ErrReqFailedMaxRetries, lastErr)
		}

		// Success case
		if c.throttler.IsThrottableRespCode(resp.StatusCode()) {
			c.throttler.EnableThrottler()
		}
		return elapsed.Milliseconds(), nil
	}

	return 0, lastErr
}

// DoRequest performs a HTTP request (raw)
// Returns the HTTP response time (in ms) and error
func (c *HTTPClient) DoRequest(req *fasthttp.Request, resp *fasthttp.Response, job payload.PayloadJob) (int64, error) {
	// Execute request with retry handling
	respTime, err := c.execFunc(req, resp, job)

	if err != nil {
		if err == ErrReqFailedMaxRetries {
			newCount := c.consecutiveFailedReqs.Add(1)
			if newCount >= int32(c.options.MaxConsecutiveFailedReqs) {
				return respTime, ErrReqFailedMaxConsecutiveFails
			}
		}

		return respTime, fmt.Errorf("request failed after %d retries: %w",
			c.retryConfig.GetPerReqRetriedAttempts(), err)
	}

	return respTime, nil
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

func applyReqCopyConfig(reqCopy *fasthttp.Request) {
	reqCopy.URI().DisablePathNormalizing = true
	reqCopy.Header.DisableNormalizing()
	reqCopy.Header.SetNoDefaultContentType(true)
	reqCopy.UseHostHeader = true
}

func ReqCopyToWithSettings(src *fasthttp.Request) *fasthttp.Request {
	dst := fasthttp.AcquireRequest()

	// Copy basic request data
	src.CopyTo(dst)

	// Apply all required settings
	dst.URI().DisablePathNormalizing = true
	dst.Header.DisableNormalizing()
	dst.Header.SetNoDefaultContentType(true)
	dst.UseHostHeader = true

	// Ensure raw path preservation
	dst.URI().SetScheme(string(src.URI().Scheme()))
	dst.URI().SetHost(string(src.URI().Host()))

	return dst
}
