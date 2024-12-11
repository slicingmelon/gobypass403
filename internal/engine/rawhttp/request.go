package rawhttp

import (
	"context"
	"fmt"
	"time"

	"github.com/valyala/fasthttp"
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

	return req
}

// SendRequest sends a raw HTTP request and returns the response
func (c *Client) SendRequest(req *Request) (*fasthttp.Response, error) {
	if req.ctx == nil {
		return nil, fmt.Errorf("context cannot be nil")
	}

	resp := fasthttp.AcquireResponse()

	// Use DoTimeout if request timeout is set
	if req.timeout > 0 {
		if err := c.client.DoTimeout(req.Request, resp, req.timeout); err != nil {
			fasthttp.ReleaseResponse(resp)
			return nil, err
		}
		return resp, nil
	}

	// Otherwise use context-based execution
	done := make(chan error, 1)
	go func() {
		done <- c.DoRaw(req.Request, resp)
	}()

	select {
	case <-req.ctx.Done():
		c.client.CloseIdleConnections()
		return nil, req.ctx.Err()
	case err := <-done:
		if err != nil {
			fasthttp.ReleaseResponse(resp)
			return nil, err
		}
		return resp, nil
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
