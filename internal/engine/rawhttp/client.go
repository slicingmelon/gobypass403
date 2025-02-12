package rawhttp

import (
	"crypto/tls"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	"github.com/valyala/fasthttp"
)

var (
	CustomUserAgent = []byte("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
)

// HTTPClientOptions contains configuration options for the HTTPClient
type HTTPClientOptions struct {
	BypassModule            string        // ScannerCliOpts
	Timeout                 time.Duration // ScannerCliOpts
	DialTimeout             time.Duration // Custom Dial Timeout
	MaxConnsPerHost         int           // fasthttp core
	MaxIdleConnDuration     time.Duration // fasthttp core
	MaxConnWaitTimeout      time.Duration // fasthttp core
	NoDefaultUserAgent      bool          // fasthttp core
	ProxyURL                string        // ScannerCliOpts
	MaxResponseBodySize     int           // fasthttp core
	ReadBufferSize          int           // fasthttp core
	WriteBufferSize         int           // fasthttp core
	MaxRetries              int           // ScannerCliOpts
	ResponseBodyPreviewSize int           // ScannerCliOpts
	StreamResponseBody      bool          // fasthttp core
	MatchStatusCodes        []int         // ScannerCliOpts
	RetryDelay              time.Duration // ScannerCliOpts
	DisableKeepAlive        bool
	EnableHTTP2             bool
	Dialer                  fasthttp.DialFunc
	RequestDelay            time.Duration // ScannerCliOpts
	IsTLS                   bool          // fasthttp core
}

// HTTPClient represents a reusable HTTP client
type HTTPClient struct {
	client           *fasthttp.Client
	options          *HTTPClientOptions
	errorHandler     *GB403ErrorHandler.ErrorHandler
	retryConfig      *RetryConfig
	retryCount       map[string]int
	mu               sync.RWMutex
	lastResponseTime atomic.Int64
}

// DefaultHTTPClientOptions returns the default HTTP client options
func DefaultHTTPClientOptions() *HTTPClientOptions {
	return &HTTPClientOptions{
		BypassModule:        "",
		Timeout:             20000 * time.Millisecond,
		DialTimeout:         5 * time.Second,
		MaxConnsPerHost:     128,
		MaxIdleConnDuration: 1 * time.Minute, // Idle keep-alive connections are closed after this duration.
		MaxConnWaitTimeout:  1 * time.Second, // Maximum duration for waiting for a free connection.
		NoDefaultUserAgent:  true,
		MaxResponseBodySize: 8192,  // Hardlimit at 8KB
		ReadBufferSize:      12288, // Hardlimit at 12KB
		WriteBufferSize:     12288, // Hardlimit at 12KB
		StreamResponseBody:  true,
		MaxRetries:          2,
		RetryDelay:          1000 * time.Millisecond,
		RequestDelay:        0,
		DisableKeepAlive:    false, // Keep connections alive
		Dialer:              nil,
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

// // GetHTTPClientOptions returns the HTTP client options
// func (c *HTTPClient) GetHTTPClientOptions() *HTTPClientOptions {
// 	c.mu.RLock()
// 	defer c.mu.RUnlock()
// 	return c.options
// }

// // SetOptions updates the client options
// func (c *HTTPClient) SetHTTPClientOptions(opts *HTTPClientOptions) {
// 	c.mu.Lock()
// 	defer c.mu.Unlock()
// 	c.options = opts
// }

func (c *HTTPClient) GetHTTPClientOptions() HTTPClientOptions {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return *c.options // Return a copy
}

// SetHTTPClientOptions updates the client options with a copy
func (c *HTTPClient) SetHTTPClientOptions(opts HTTPClientOptions) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.options = &opts // Store a copy
}

// func (c *HTTPClient) execFunc(req *fasthttp.Request, resp *fasthttp.Response) (int64, error) {
// 	c.retryConfig.ResetPerReqAttempts()
// 	var lastErr error

// 	reqCopy := fasthttp.AcquireRequest()
// 	defer fasthttp.ReleaseRequest(reqCopy)
// 	req.CopyTo(reqCopy)

// 	for attempt := 0; attempt <= c.options.MaxRetries; attempt++ {
// 		// Apply request delay before first request
// 		if attempt == 0 && c.GetHTTPClientOptions().RequestDelay > 0 {
// 			time.Sleep(c.GetHTTPClientOptions().RequestDelay)
// 		}

// 		// Apply retry delay before retry attempts
// 		if attempt > 0 {
// 			time.Sleep(c.options.RetryDelay)
// 		}

// 		start := time.Now()
// 		err := c.client.DoTimeout(reqCopy, resp, c.options.Timeout+c.options.RetryDelay)
// 		lastErr = err

// 		if err == nil {
// 			return time.Since(start).Milliseconds(), nil
// 		}

// 		if !IsRetryableError(err) {
// 			return time.Since(start).Milliseconds(), err
// 		}

// 		// Prepare for next retry
// 		if attempt < c.options.MaxRetries {
// 			opts := c.GetHTTPClientOptions()
// 			opts.DisableKeepAlive = true
// 			c.SetHTTPClientOptions(opts)

// 			reqCopy.Header.Del("Connection")
// 			reqCopy.SetConnectionClose()
// 			reqCopy.Header.Set("X-Retry", fmt.Sprintf("%d", attempt+1))

// 			c.retryConfig.PerReqRetriedAttempts.Add(1)
// 			resp.Reset()
// 		}
// 	}

// 	return 0, fmt.Errorf("max retries reached: %w", lastErr)
// }

func (c *HTTPClient) execFunc(req *fasthttp.Request, resp *fasthttp.Response) (int64, error) {
	c.retryConfig.ResetPerReqAttempts()
	var lastErr error

	reqCopy := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(reqCopy)
	req.CopyTo(reqCopy)

	for attempt := 0; attempt <= c.options.MaxRetries; attempt++ {
		// Apply request delay before first request
		if attempt == 0 {
			reqDelay := c.GetHTTPClientOptions().RequestDelay
			if reqDelay > 0 {
				time.Sleep(reqDelay)
			}
		}

		// Apply retry delay before retry attempts
		if attempt > 0 {
			retryDelay := c.GetHTTPClientOptions().RetryDelay
			time.Sleep(retryDelay)
		}

		start := time.Now()

		var timeout time.Duration
		timeout = c.GetHTTPClientOptions().Timeout
		if attempt > 0 {
			timeout += c.options.RetryDelay // Only add delay for retry attempts
		}

		err := c.client.DoTimeout(reqCopy, resp, timeout)
		lastErr = err

		if err == nil {
			return time.Since(start).Milliseconds(), nil
		}

		if !IsRetryableError(err) {
			return time.Since(start).Milliseconds(), err
		}

		// Prepare for next retry
		if attempt < c.options.MaxRetries {
			opts := c.GetHTTPClientOptions()
			opts.DisableKeepAlive = true
			c.SetHTTPClientOptions(opts)

			reqCopy.Header.Del("Connection")
			reqCopy.SetConnectionClose()
			reqCopy.Header.Set("X-Retry", fmt.Sprintf("%d", attempt+1))

			c.retryConfig.PerReqRetriedAttempts.Add(1)
			resp.Reset()
		}
	}

	return 0, fmt.Errorf("max retries reached: %w", lastErr)
}

// DoRequest performs a HTTP request (raw)
// Returns the HTTP response time (in ms) and error
func (c *HTTPClient) DoRequest(req *fasthttp.Request, resp *fasthttp.Response) (int64, error) {
	// Execute request with retry handling
	respTime, err := c.execFunc(req, resp)

	if err != nil {
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
