package rawhttp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
	"golang.org/x/net/http/httpproxy"
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
	EnableHTTP2         bool
}

// Client represents a reusable HTTP client optimized for performance
type Client struct {
	client       *fasthttp.Client
	bufPool      sync.Pool
	userAgent    []byte
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
		ReadBufferSize:      4096,
		MaxRetries:          3,
		RetryDelay:          1 * time.Second,
		DisableKeepAlive:    true, // Set to true for multi-host scanning
	}
}

// DefaultOptionsSingleHost returns options optimized for scanning a single host
func DefaultOptionsSameHost() *ClientOptions {
	return &ClientOptions{
		Timeout:             30 * time.Second,
		MaxConnsPerHost:     64,
		MaxIdleConnDuration: 10 * time.Second,
		MaxConnWaitTimeout:  2 * time.Second,
		NoDefaultUserAgent:  true,
		ReadBufferSize:      4096,
		MaxRetries:          3,
		RetryDelay:          1 * time.Second,
		DisableKeepAlive:    false, // Keep connections alive for single host
	}
}

// / NewHTTPClient creates a new optimized HTTP client
func NewClient(opts *ClientOptions, errorHandler *GB403ErrorHandler.ErrorHandler) *Client {
	if opts == nil {
		opts = DefaultOptionsSameHost()
	}

	d := fasthttpproxy.Dialer{
		TCPDialer: fasthttp.TCPDialer{
			Concurrency:      2048,
			DNSCacheDuration: time.Hour,
		},
		Config: httpproxy.Config{
			HTTPProxy:  opts.ProxyURL,
			HTTPSProxy: opts.ProxyURL,
			NoProxy:    "*",
		},
		ConnectTimeout: 5 * time.Second,
		DialDualStack:  false,
	}

	// Get the dial function and handle any initial errors
	dialFunc, err := d.GetDialFunc(false)
	if err != nil && errorHandler != nil {
		errorHandler.HandleError("Dialer", err)
	}

	wrappedDialFunc := func(addr string) (net.Conn, error) {
		conn, err := dialFunc(addr)
		if err != nil {
			if errorHandler != nil {
				var dialErr *fasthttp.ErrDialWithUpstream
				switch {
				case errors.Is(err, fasthttp.ErrDialTimeout):
					errorHandler.HandleError("Dial", fmt.Errorf("timeout connecting to %s: %w", addr, err))
				case errors.As(err, &dialErr):
					// Handle DNS and proxy errors
					switch {
					case strings.Contains(dialErr.Error(), "no such host") ||
						strings.Contains(dialErr.Error(), "no DNS entries"):
						errorHandler.HandleError("DNS", fmt.Errorf("DNS resolution failed for %s: %w", addr, err))
					case strings.Contains(dialErr.Error(), "proxy"):
						errorHandler.HandleError("Proxy", fmt.Errorf("proxy error for %s: %w", addr, err))
					default:
						errorHandler.HandleError("Dial", fmt.Errorf("connection failed to %s: %w", addr, err))
					}
				default:
					errorHandler.HandleError("Dial", fmt.Errorf("error connecting to %s: %w", addr, err))
				}
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
		ReadBufferSize:                opts.ReadBufferSize,
		MaxIdemponentCallAttempts:     opts.MaxRetries,
		Dial:                          wrappedDialFunc,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return &Client{
		client:       client,
		errorHandler: errorHandler,
		bufPool:      sync.Pool{New: func() interface{} { return make([]byte, 0, opts.ReadBufferSize) }},
		userAgent:    userAgent,
		maxRetries:   opts.MaxRetries,
		retryDelay:   opts.RetryDelay,
		options:      opts,
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
