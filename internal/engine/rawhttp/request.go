package rawhttp

import (
	"bytes"
	"context"
	"math/rand"
	"sync"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/valyala/fasthttp"
)

const (
	DefaultBodyPreviewSize = 2 * 1024        // 2KB preview
	DefaultMaxResponseSize = 5 * 1024 * 1024 // 5MB total
)

var (
	// Pre-generate the charset table for faster lookups
	charsetTable = func() [62]byte {
		// Initialize with 62 chars (26 lowercase + 26 uppercase + 10 digits)
		var table [62]byte

		// 0-9 (10 chars)
		for i := 0; i < 10; i++ {
			table[i] = byte(i) + '0'
		}

		// A-Z (26 chars)
		for i := 0; i < 26; i++ {
			table[i+10] = byte(i) + 'A'
		}

		// a-z (26 chars)
		for i := 0; i < 26; i++ {
			table[i+36] = byte(i) + 'a'
		}

		return table
	}()

	// Use a concurrent-safe random source
	rnd = rand.New(rand.NewSource(time.Now().UnixNano()))
	mu  sync.Mutex
)

// Request represents a raw HTTP request with context support
type Request struct {
	*fasthttp.Request
	ctx     context.Context
	timeout time.Duration
}

type Header struct {
	Key   string
	Value string
}

// NewRequestWithContext creates a new Request with context
func NewRequestWithContext(ctx context.Context, method, url string, headers map[string]string) *Request {
	req := &Request{
		Request: fasthttp.AcquireRequest(),
		ctx:     ctx,
	}

	req.Header.SetMethod(method)
	req.SetRequestURI(url)

	// Configure raw request handling
	req.URI().DisablePathNormalizing = true
	req.Header.DisableNormalizing()
	req.Header.SetNoDefaultContentType(true)

	// Set headers at creation time
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	canary := generateRandomString(18)
	if logger.IsDebugEnabled() {
		req.Header.Set("X-GB403-Debug", canary)
	}

	return req
}

// ResponseDetails contains processed response information
type ResponseDetails struct {
	StatusCode      int
	ResponsePreview string
	ResponseHeaders string
	ContentType     string
	ContentLength   int64
	ServerInfo      string
	RedirectURL     string
	ResponseBytes   int
	Title           string
	BodyLimitHit    bool
}

// SendRequest handles the complete request cycle using the configured client
func (c *Client) SendRequest(method, url string, headers map[string]string) (*ResponseDetails, error) {
	// Acquire request and response objects from pool
	req := c.AcquireRequest()
	resp := c.AcquireResponse()
	defer c.ReleaseRequest(req)
	defer c.ReleaseResponse(resp)

	// Setup request
	req.SetRequestURI(url)
	req.Header.SetMethod(method)
	req.URI().DisablePathNormalizing = true
	req.Header.DisableNormalizing()
	req.Header.SetNoDefaultContentType(true)

	// Set headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Perform request with configured client options (including retries)
	if err := c.DoRaw(req, resp); err != nil {
		return nil, err
	}

	return c.processResponse(resp), nil
}

// processResponse handles response processing and data extraction
func (c *Client) processResponse(resp *fasthttp.Response) *ResponseDetails {
	details := &ResponseDetails{
		StatusCode:    resp.StatusCode(),
		ContentType:   string(resp.Header.Peek("Content-Type")),
		ContentLength: int64(resp.Header.ContentLength()),
		ServerInfo:    string(resp.Header.Peek("Server")),
		RedirectURL:   string(resp.Header.Peek("Location")),
	}

	// Process headers
	var headerBuf bytes.Buffer
	resp.Header.VisitAll(func(key, value []byte) {
		headerBuf.Write(key)
		headerBuf.WriteString(": ")
		headerBuf.Write(value)
		headerBuf.WriteString("\n")
	})
	details.ResponseHeaders = headerBuf.String()

	// Process body with size limits
	body := resp.Body()
	details.ResponseBytes = len(body)

	// Use configured ReadBufferSize if available
	maxSize := DefaultMaxResponseSize
	if c.options.ReadBufferSize > 0 {
		maxSize = c.options.ReadBufferSize
	}

	if len(body) > maxSize {
		details.BodyLimitHit = true
		body = body[:maxSize]
	}

	// Create preview
	if len(body) > DefaultBodyPreviewSize {
		details.ResponsePreview = string(body[:DefaultBodyPreviewSize]) + "..."
	} else {
		details.ResponsePreview = string(body)
	}

	return details
}

// doRequestWithTimeout handles the actual request with proper timeout
func (c *Client) doRequestWithTimeout(req *Request, resp *fasthttp.Response) error {
	done := make(chan error, 1)
	go func() {
		done <- c.DoRaw(req.Request, resp)
	}()

	select {
	case <-req.ctx.Done():
		c.client.CloseIdleConnections()
		return req.ctx.Err()
	case err := <-done:
		return err
	}
}

// SetHeaderBytes sets a header using byte slices
func (r *Request) SetHeaderBytes(key, value []byte) {
	r.Header.SetBytesKV(key, value)
}

// SetRequestURIBytes sets the request URI using a byte slice
func (r *Request) SetRequestURIBytes(uri []byte) {
	r.Request.SetRequestURIBytes(uri)
	r.URI().DisablePathNormalizing = true
}

// SetHeader sets a header value
func (r *Request) SetHeader(key, value string) {
	r.Header.Set(key, value)
}

// SetHeaders sets multiple headers from a map
func (r *Request) SetHeaders(headers map[string]string) {
	for key, value := range headers {
		r.Header.Set(key, value)
	}
}

// SetBody sets the request body
func (r *Request) SetBody(body []byte) {
	r.SetBody(body)
}

// SetTimeout sets request timeout
func (r *Request) SetTimeout(timeout time.Duration) {
	r.timeout = timeout
}

// Release releases request resources back to pool
func (r *Request) Release() {
	if r.Request != nil {
		fasthttp.ReleaseRequest(r.Request)
		r.Request = nil
	}
}

// Helper function to generate random strings
// generateRandomString creates a random string using pre-generated table
func generateRandomString(length int) string {
	b := make([]byte, length)
	tableSize := uint32(len(charsetTable))

	mu.Lock()
	for i := range b {
		// Using uint32 for better performance than modulo
		b[i] = charsetTable[rnd.Uint32()%tableSize]
	}
	mu.Unlock()

	return string(b)
}
