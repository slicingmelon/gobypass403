package rawhttp

import (
	"crypto/tls"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
)

var (
	userAgent = []byte("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
)

// ClientOptions contains configuration options for the Client
type ClientOptions struct {
	Timeout             time.Duration
	MaxConnsPerHost     int
	MaxIdleConnDuration time.Duration
	MaxConnWaitTimeout  time.Duration
	NoDefaultUserAgent  bool
	ProxyURL            string
	ReadBufferSize      int
	MaxRetries          int
	RetryDelay          time.Duration
	DisableKeepAlive    bool
}

// Client represents a reusable HTTP client optimized for performance
type Client struct {
	client     *fasthttp.Client
	bufPool    sync.Pool
	userAgent  []byte
	maxRetries int
	retryDelay time.Duration
	options    *ClientOptions
}

// DefaultOptionsMultiHost returns options optimized for scanning multiple hosts
func DefaultOptionsMultiHost() *ClientOptions {
	return &ClientOptions{
		Timeout:             30 * time.Second,
		MaxConnsPerHost:     25,
		MaxIdleConnDuration: 5 * time.Second,
		NoDefaultUserAgent:  true,
		ProxyURL:            "",
		MaxRetries:          3,
		RetryDelay:          1 * time.Second,
		DisableKeepAlive:    true, // Set to true for multi-host scanning
	}
}

// DefaultOptionsSingleHost returns options optimized for scanning a single host
func DefaultOptionsSingleHost() *ClientOptions {
	return &ClientOptions{
		Timeout:             30 * time.Second,
		MaxConnsPerHost:     128,
		MaxIdleConnDuration: 10 * time.Second,
		MaxConnWaitTimeout:  2 * time.Second,
		NoDefaultUserAgent:  true,
		ProxyURL:            "",
		ReadBufferSize:      4096,
		MaxRetries:          5,
		RetryDelay:          1 * time.Second,
		DisableKeepAlive:    false, // Keep connections alive for single host
	}
}

// / NewHTTPClient creates a new optimized HTTP client
func NewClient(opts *ClientOptions) *Client {
	if opts == nil {
		opts = DefaultOptionsSingleHost()
	}

	// Configure dialer based on proxy settings
	var dialFunc fasthttp.DialFunc
	if opts.ProxyURL != "" {
		dialFunc = fasthttpproxy.FasthttpHTTPDialerTimeout(opts.ProxyURL, opts.Timeout)
	} else {
		dialFunc = (&fasthttp.TCPDialer{
			Concurrency:      100,
			DNSCacheDuration: time.Minute,
		}).Dial
	}

	client := &fasthttp.Client{
		Dial:                          dialFunc,
		ReadTimeout:                   opts.Timeout,
		WriteTimeout:                  opts.Timeout,
		MaxConnsPerHost:               opts.MaxConnsPerHost,
		MaxIdleConnDuration:           opts.MaxIdleConnDuration,
		DisableHeaderNamesNormalizing: true,
		DisablePathNormalizing:        true,
		NoDefaultUserAgentHeader:      true,
		ReadBufferSize:                opts.ReadBufferSize,
		MaxIdemponentCallAttempts:     1,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
	}

	return &Client{
		client:    client,
		bufPool:   sync.Pool{New: func() interface{} { return make([]byte, 0, opts.ReadBufferSize) }},
		userAgent: userAgent,
		options:   opts,
	}
}

// DoRaw performs a raw HTTP request
func (c *Client) DoRaw(req *fasthttp.Request, resp *fasthttp.Response) error {
	// Set max body size before making the request
	return c.client.Do(req, resp)
}

// AcquireBuffer gets a buffer from the pool
func (c *Client) AcquireBuffer() []byte {
	return c.bufPool.Get().([]byte)
}

// ReleaseBuffer returns a buffer to the pool
func (c *Client) ReleaseBuffer(buf []byte) {
	// Reset the buffer before returning it to the pool
	buf = buf[:0]
	c.bufPool.Put(buf)
}

// Close releases all idle connections
func (c *Client) Close() {
	c.client.CloseIdleConnections()
}

// AcquireRequest returns a new Request instance from pool
func (c *Client) AcquireRequest() *fasthttp.Request {
	return fasthttp.AcquireRequest()
}

// ReleaseRequest returns request to pool
func (c *Client) ReleaseRequest(req *fasthttp.Request) {
	fasthttp.ReleaseRequest(req)
}

// AcquireResponse returns a new Response instance from pool
func (c *Client) AcquireResponse() *fasthttp.Response {
	return fasthttp.AcquireResponse()
}

// ReleaseResponse returns response to pool
func (c *Client) ReleaseResponse(resp *fasthttp.Response) {
	fasthttp.ReleaseResponse(resp)
}
