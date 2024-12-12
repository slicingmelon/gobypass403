package rawhttp

import (
	"context"
	"math/rand"
	"sync"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/valyala/fasthttp"
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

type responseDetails struct {
	StatusCode      int
	ResponsePreview string
	ResponseHeaders string
	ContentType     string
	ContentLength   int64
	ServerInfo      string
	RedirectURL     string
	ResponseBytes   int
	Title           string
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

// SendRequest sends a raw HTTP request and returns the response
func (c *Client) SendRequest(req *Request) (*responseDetails, error) {
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	if err := c.doRequestWithTimeout(req, resp); err != nil {
		return &responseDetails{StatusCode: resp.StatusCode()}, err
	}

	// Always return status code even if body processing fails
	details := &responseDetails{
		StatusCode: resp.StatusCode(),
	}

	// Process headers (lightweight operation)
	details.ResponseHeaders = resp.Header.String()
	details.ContentType = string(resp.Header.ContentType())
	details.ContentLength = int64(resp.Header.ContentLength())
	details.ServerInfo = string(resp.Header.Peek("Server"))

	if location := resp.Header.Peek("Location"); len(location) > 0 {
		details.RedirectURL = string(location)
	}

	// Process body with proper error handling
	if body := resp.Body(); len(body) > 0 {
		details.ResponseBytes = len(body)
		details.ResponsePreview = string(body)
	}

	return details, nil
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
