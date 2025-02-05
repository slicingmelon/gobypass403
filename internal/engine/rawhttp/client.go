package rawhttp

import (
	"crypto/tls"
	"sync"
	"time"

	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	"github.com/valyala/fasthttp"
)

var (
	CustomUserAgent = []byte("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
)

// HTTPClientOptions contains configuration options for the HTTPClient
type HTTPClientOptions struct {
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
}

// HTTPClient represents a reusable HTTP client
type HTTPClient struct {
	client       *fasthttp.Client
	options      *HTTPClientOptions
	errorHandler *GB403ErrorHandler.ErrorHandler
	retryConfig  *RetryConfig
	mu           sync.RWMutex
}

// DefaultHTTPClientOptions returns the default HTTP client options
func DefaultHTTPClientOptions() *HTTPClientOptions {
	return &HTTPClientOptions{
		Timeout:             20 * time.Second,
		DialTimeout:         5 * time.Second,
		MaxConnsPerHost:     128,
		MaxIdleConnDuration: 1 * time.Minute, // Idle keep-alive connections are closed after this duration.
		MaxConnWaitTimeout:  1 * time.Second, // Maximum duration for waiting for a free connection.
		NoDefaultUserAgent:  true,
		MaxResponseBodySize: 8192,  // Hardlimit at 8KB
		ReadBufferSize:      12288, // Hardlimit at 12KB
		WriteBufferSize:     12288, // Hardlimit at 12KB
		StreamResponseBody:  true,
		MaxRetries:          3,
		RetryDelay:          1 * time.Second,
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
		ReadTimeout:                   opts.Timeout,
		WriteTimeout:                  opts.Timeout,
		Dial:                          CreateDialFunc(opts, errorHandler),
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		},
	}

	return &HTTPClient{
		client:       client,
		options:      opts,
		errorHandler: errorHandler,
		retryConfig:  DefaultRetryConfig(), // Use default retry config
		mu:           sync.RWMutex{},       // Initialize mutex properly
	}
}

// GetHTTPClientOptions returns the HTTP client options
func (c *HTTPClient) GetHTTPClientOptions() *HTTPClientOptions {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.options
}

// SetOptions updates the client options
func (c *HTTPClient) SetHTTPClientOptions(opts *HTTPClientOptions) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.options = opts
}

// DoRequest performs a HTTP request (raw)
func (c *HTTPClient) DoRequest(req *fasthttp.Request, resp *fasthttp.Response) error {
	return c.client.Do(req, resp)
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
