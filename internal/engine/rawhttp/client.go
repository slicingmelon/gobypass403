package rawhttp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
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
}

// HTTPClient represents a reusable HTTP client
type HTTPClient struct {
	client                *fasthttp.Client
	options               *HTTPClientOptions
	errorHandler          *GB403ErrorHandler.ErrorHandler
	retryConfig           *RetryConfig
	mu                    sync.RWMutex
	lastResponseTime      atomic.Int64
	consecutiveFailedReqs atomic.Int32
}

// DefaultHTTPClientOptions returns the default HTTP client options
func DefaultHTTPClientOptions() *HTTPClientOptions {
	return &HTTPClientOptions{
		BypassModule:             "",
		Timeout:                  20000 * time.Millisecond,
		DialTimeout:              5 * time.Second,
		MaxConnsPerHost:          128,
		MaxIdleConnDuration:      1 * time.Minute, // Idle keep-alive connections are closed after this duration.
		MaxConnWaitTimeout:       1 * time.Second, // Maximum duration for waiting for a free connection.
		NoDefaultUserAgent:       true,
		MaxResponseBodySize:      8192,  // Hardlimit at 8KB
		ReadBufferSize:           12288, // Hardlimit at 12KB
		WriteBufferSize:          12288, // Hardlimit at 12KB
		StreamResponseBody:       true,
		MaxRetries:               2,
		RetryDelay:               1000 * time.Millisecond,
		RequestDelay:             0,
		DisableKeepAlive:         false, // Keep connections alive
		Dialer:                   nil,
		MaxConsecutiveFailedReqs: 15,
	}
}

// NewHTTPClient creates a new HTTP client instance
func NewHTTPClient(opts *HTTPClientOptions, errorHandler *GB403ErrorHandler.ErrorHandler) *HTTPClient {
	if opts == nil {
		opts = DefaultHTTPClientOptions()
	}

	retryConfig := DefaultRetryConfig()
	retryConfig.MaxRetries = opts.MaxRetries
	retryConfig.RetryDelay = opts.RetryDelay

	c := &HTTPClient{
		options:      opts,
		errorHandler: errorHandler,
		retryConfig:  retryConfig,
	}

	// reset failed consecutive requests
	c.ResetConsecutiveFailedReqs()

	client := &fasthttp.Client{
		MaxConnsPerHost:               opts.MaxConnsPerHost,
		MaxIdleConnDuration:           opts.MaxIdleConnDuration,
		MaxConnWaitTimeout:            opts.MaxConnWaitTimeout,
		DisableHeaderNamesNormalizing: true,
		DisablePathNormalizing:        true,
		NoDefaultUserAgentHeader:      true,
		MaxResponseBodySize:           opts.MaxResponseBodySize,
		ReadBufferSize:                opts.ReadBufferSize,
		WriteBufferSize:               opts.WriteBufferSize,
		StreamResponseBody:            opts.StreamResponseBody,
		//ReadTimeout:                   opts.Timeout,
		//WriteTimeout:                  opts.Timeout,
		Dial: CreateDialFunc(opts, errorHandler),
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

func (c *HTTPClient) execFunc(req *fasthttp.Request, resp *fasthttp.Response) (int64, error) {
	c.retryConfig.ResetPerReqAttempts()
	//var lastErr error

	reqCopy := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(reqCopy)
	req.CopyTo(reqCopy)

	// Capture original timeout and retry delay from the global options and retry config.
	origOpts := c.GetHTTPClientOptions()
	baseTimeout := origOpts.Timeout
	retryDelay := c.retryConfig.RetryDelay
	maxRetries := c.retryConfig.MaxRetries

	// Apply the request delay to all requests (from cli opts)
	if origOpts.RequestDelay > 0 {
		time.Sleep(origOpts.RequestDelay)
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Calculate timeout for this attempt
		currentTimeout := baseTimeout
		if attempt > 0 {
			// For retry attempts:
			// 1. Sleep for retry delay
			GB403Logger.Debug().Msgf("Sleeping for retry delay: %v\n", retryDelay)
			time.Sleep(retryDelay)

			// 2. Increase timeout based on attempt number
			currentTimeout = baseTimeout + time.Duration(attempt)*retryDelay

			// 3. Disable keep-alive for retries
			reqCopy.SetConnectionClose()
		}

		GB403Logger.Debug().Msgf("Attempt %d: timeout=%v (base=%v)\n", attempt, currentTimeout, baseTimeout)

		start := time.Now()
		err := c.client.DoTimeout(reqCopy, resp, currentTimeout)
		elapsed := time.Since(start)

		GB403Logger.Debug().Msgf("Attempt %d completed in %v with error: %v\n", attempt, elapsed, err)
		//lastErr = err

		if err == nil {
			return elapsed.Milliseconds(), nil
		}

		if !IsRetryableError(err) {
			GB403Logger.Debug().Msgf("Non-retryable error: %v\n", err)
			return elapsed.Milliseconds(), err
		}

		if attempt < maxRetries {
			// Prepare req for next retry
			reqCopy.Header.Del("Connection")
			reqCopy.Header.Set("X-Retry", fmt.Sprintf("%d", attempt+1))
			c.retryConfig.PerReqRetriedAttempts.Add(1)
			resp.Reset()
		}

		// Signal max retries reached
		if attempt == maxRetries {
			return 0, ErrReqFailedMaxRetries
		}
	}

	return 0, nil
}

// DoRequest performs a HTTP request (raw)
// Returns the HTTP response time (in ms) and error
func (c *HTTPClient) DoRequest(req *fasthttp.Request, resp *fasthttp.Response) (int64, error) {
	// Execute request with retry handling
	respTime, err := c.execFunc(req, resp)

	if err != nil {
		if err == ErrReqFailedMaxRetries {
			// Increment consecutive failures counter
			newCount := c.consecutiveFailedReqs.Add(1)

			// Check if we've hit max consecutive failures
			if newCount >= int32(c.options.MaxConsecutiveFailedReqs) {
				return respTime, ErrReqFailedMaxConsecutiveFails
			}
		}

		// Handle the error first
		handleErr := c.errorHandler.HandleError(err, GB403ErrorHandler.ErrorContext{
			ErrorSource:  []byte("HTTPClient.DoRequest"),
			Host:         append([]byte(nil), req.Host()...),
			BypassModule: []byte(c.options.BypassModule),
		})

		if handleErr != nil {
			// If error handling itself failed, we should probably know about it
			return respTime, fmt.Errorf("request failed after %d retries and error handling failed: %w (handler error: %v)",
				c.retryConfig.GetPerReqRetriedAttempts(), err, handleErr)
		}

		// Return original error with retry context
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

// GetLastResponseTime returns the last HTTP response time in milliseconds
func (c *HTTPClient) GetLastResponseTime() int64 {
	return c.lastResponseTime.Load()
}

// Close releases all idle connections
func (c *HTTPClient) Close() {
	c.client.CloseIdleConnections()
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
