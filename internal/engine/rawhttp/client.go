package rawhttp

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
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
}

// Client represents a reusable HTTP client optimized for performance
type HttpClient struct {
	client       *fasthttp.Client
	bufPool      sync.Pool
	maxRetries   int
	retryDelay   time.Duration
	options      *ClientOptions
	logger       *GB403Logger.Logger
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
	}
}

// DefaultOptionsSingleHost returns options optimized for scanning a single host
func DefaultOptionsSameHost() *ClientOptions {
	return &ClientOptions{
		Timeout:             30 * time.Second,
		MaxConnsPerHost:     512,
		MaxIdleConnDuration: 10 * time.Second,
		MaxConnWaitTimeout:  2 * time.Second,
		NoDefaultUserAgent:  true,
		MaxResponseBodySize: 4096, // Hardlimit at 4k
		ReadBufferSize:      4096,
		WriteBufferSize:     4096,
		MaxRetries:          3,
		RetryDelay:          1 * time.Second,
		DisableKeepAlive:    false, // Keep connections alive for single host
	}
}

// / NewHTTPClient creates a new optimized HTTP client
func NewClient(opts *ClientOptions, errorHandler *GB403ErrorHandler.ErrorHandler, logger *GB403Logger.Logger) *HttpClient {
	if opts == nil {
		opts = DefaultOptionsSameHost()
	}

	// Create a custom TCPDialer with our settings
	dialer := &fasthttp.TCPDialer{
		Concurrency:      2048,
		DNSCacheDuration: 15 * time.Minute,
	}

	// Create the dial function that handles both proxy and direct connections
	dialFunc := func(addr string) (net.Conn, error) {
		if opts.ProxyURL != "" {
			proxyDialer := fasthttpproxy.FasthttpHTTPDialerTimeout(opts.ProxyURL, 3*time.Second)
			conn, err := proxyDialer(addr)
			if err != nil {
				if handleErr := errorHandler.HandleError(err, GB403ErrorHandler.ErrorContext{
					ErrorSource: []byte("Client.proxyDial"),
					Host:        []byte(addr),
				}); handleErr != nil {
					return nil, fmt.Errorf("proxy dial error handling failed: %v (original error: %v)", handleErr, err)
				}
				return nil, err
			}
			return conn, nil
		}

		// No proxy, use our TCPDialer with timeout
		conn, err := dialer.DialTimeout(addr, 5*time.Second)
		if err != nil {
			if handleErr := errorHandler.HandleError(err, GB403ErrorHandler.ErrorContext{
				ErrorSource: []byte("Client.directDial"),
				Host:        []byte(addr),
			}); handleErr != nil {
				return nil, fmt.Errorf("direct dial error handling failed: %v (original error: %v)", handleErr, err)
			}
			return nil, err
		}
		return conn, nil
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
		Dial:                          dialFunc,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return &HttpClient{
		client:       client,
		errorHandler: errorHandler,
		bufPool:      sync.Pool{New: func() interface{} { return make([]byte, 0, opts.ReadBufferSize) }},
		maxRetries:   opts.MaxRetries,
		retryDelay:   opts.RetryDelay,
		options:      opts,
		logger:       logger,
	}
}

// DoRaw performs a raw HTTP request
func (c *HttpClient) DoRaw(req *fasthttp.Request, resp *fasthttp.Response) error {
	// Set max body size before making the request
	return c.client.Do(req, resp)
}

// AcquireBuffer gets a buffer from the pool
func (c *HttpClient) AcquireBuffer() []byte {
	return c.bufPool.Get().([]byte)
}

// ReleaseBuffer returns a buffer to the pool
func (c *HttpClient) ReleaseBuffer(buf []byte) {
	// Reset the buffer before returning it to the pool
	buf = buf[:0]
	c.bufPool.Put(buf)
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
