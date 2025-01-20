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

// ClientOptions contains configuration options for the Client
type ClientOptions struct {
	Timeout             time.Duration
	MaxConnsPerHost     int
	MaxIdleConnDuration time.Duration
	MaxConnWaitTimeout  time.Duration
	NoDefaultUserAgent  bool
	ProxyURL            string
	MaxResponseBodySize int
	ReadBufferSize      int
	WriteBufferSize     int
	MaxRetries          int
	RetryDelay          time.Duration
	DisableKeepAlive    bool
	EnableHTTP2         bool
	Dialer              fasthttp.DialFunc
}

// Client represents a reusable HTTP client optimized for performance
type HttpClient struct {
	client       *fasthttp.Client
	bufPool      sync.Pool
	maxRetries   int
	retryDelay   time.Duration
	options      *ClientOptions
	errorHandler *GB403ErrorHandler.ErrorHandler
}

// DefaultOptionsMultiHost returns options optimized for scanning multiple hosts
func DefaultOptionsMultiHost() *ClientOptions {
	return &ClientOptions{
		Timeout:             30 * time.Second,
		MaxConnsPerHost:     25,
		MaxIdleConnDuration: 5 * time.Second,
		NoDefaultUserAgent:  true,
		MaxResponseBodySize: 4096, // Hardlimit at 4k
		ReadBufferSize:      4096,
		WriteBufferSize:     4096,
		MaxRetries:          3,
		RetryDelay:          1 * time.Second,
		DisableKeepAlive:    true, // Set to true for multi-host scanning
		Dialer:              nil,
	}
}

// DefaultOptionsSingleHost returns options optimized for scanning a single host
func DefaultOptionsSameHost() *ClientOptions {
	return &ClientOptions{
		Timeout:             30 * time.Second,
		MaxConnsPerHost:     128,
		MaxIdleConnDuration: 10 * time.Second,
		MaxConnWaitTimeout:  2 * time.Second,
		NoDefaultUserAgent:  true,
		MaxResponseBodySize: 4096, // Hardlimit at 4k
		ReadBufferSize:      4096,
		WriteBufferSize:     4096,
		MaxRetries:          3,
		RetryDelay:          1 * time.Second,
		DisableKeepAlive:    false, // Keep connections alive for single host
		Dialer:              nil,
	}
}

// / NewHTTPClient creates a new optimized HTTP client
func NewHTTPClient(opts *ClientOptions, errorHandler *GB403ErrorHandler.ErrorHandler) *HttpClient {
	if opts == nil {
		opts = DefaultOptionsSameHost()
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
		MaxIdemponentCallAttempts:     opts.MaxRetries,
		Dial:                          CreateDialFunc(opts, errorHandler),
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		},
	}

	return &HttpClient{
		client:       client,
		errorHandler: errorHandler,
		bufPool:      sync.Pool{New: func() interface{} { return make([]byte, 0, opts.ReadBufferSize) }},
		maxRetries:   opts.MaxRetries,
		retryDelay:   opts.RetryDelay,
		options:      opts,
	}
}

// DoRaw performs a raw HTTP request
func (c *HttpClient) DoRaw(req *fasthttp.Request, resp *fasthttp.Response) error {
	return c.client.Do(req, resp)
}

// Close releases all idle connections
func (c *HttpClient) Close() {
	c.client.CloseIdleConnections()
}

// AcquireRequest returns a new Request instance from pool
func (c *HttpClient) AcquireRequest() *fasthttp.Request {
	return fasthttp.AcquireRequest()
}

// ReleaseRequest returns request to pool
func (c *HttpClient) ReleaseRequest(req *fasthttp.Request) {
	fasthttp.ReleaseRequest(req)
}

// AcquireResponse returns a new Response instance from pool
func (c *HttpClient) AcquireResponse() *fasthttp.Response {
	return fasthttp.AcquireResponse()
}

// ReleaseResponse returns response to pool
func (c *HttpClient) ReleaseResponse(resp *fasthttp.Response) {
	fasthttp.ReleaseResponse(resp)
}
