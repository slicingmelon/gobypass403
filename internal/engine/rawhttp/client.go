package rawhttp

import (
	"crypto/tls"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
)

const (
	userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
)

// ClientOptions contains configuration options for the Client
type ClientOptions struct {
	Timeout             time.Duration
	MaxConnsPerHost     int
	MaxIdleConnDuration time.Duration
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
		MaxConnsPerHost:     50,
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
		MaxConnsPerHost:     512,
		MaxIdleConnDuration: 10 * time.Second,
		NoDefaultUserAgent:  true,
		ProxyURL:            "",
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
		// Use FasthttpHTTPDialer for HTTP proxy support
		dialFunc = fasthttpproxy.FasthttpHTTPDialer(opts.ProxyURL)
	}

	c := &Client{
		client: &fasthttp.Client{
			Dial:                          dialFunc,
			ReadTimeout:                   opts.Timeout,
			WriteTimeout:                  opts.Timeout,
			MaxConnsPerHost:               opts.MaxConnsPerHost,
			MaxIdleConnDuration:           opts.MaxIdleConnDuration,
			DisableHeaderNamesNormalizing: true,
			DisablePathNormalizing:        true,
			NoDefaultUserAgentHeader:      true,
			ReadBufferSize:                opts.ReadBufferSize,
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
			},
		},
		bufPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 0, opts.ReadBufferSize)
			},
		},
		userAgent:  []byte(userAgent),
		maxRetries: opts.MaxRetries,
		retryDelay: opts.RetryDelay,
		options:    opts,
	}

	return c
}

// DoRaw performs a raw HTTP request with full control over the request
func (c *Client) DoRaw(req *fasthttp.Request, resp *fasthttp.Response) error {
	if !c.options.NoDefaultUserAgent && len(req.Header.Peek("User-Agent")) == 0 {
		req.Header.SetBytesV("User-Agent", c.userAgent)
	}

	if c.options.DisableKeepAlive {
		req.Header.Set("Connection", "close")
	}

	var err error
	for retry := 0; retry <= c.maxRetries; retry++ {
		if retry > 0 {
			time.Sleep(c.retryDelay)
		}

		err = c.client.Do(req, resp)
		if err == nil {
			return nil
		}

		if !isRetryableError(err) {
			return err
		}
	}

	return err
}

// isRetryableError determines if an error should trigger a retry
func isRetryableError(err error) bool {
	// TODO: Implement specific error checks for retry conditions
	// Common cases: connection errors, timeouts, temporary network issues
	return true
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
