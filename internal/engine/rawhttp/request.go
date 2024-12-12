package rawhttp

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"
	"unsafe"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
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

// RequestPool manages a pool of FastHTTP requests
type RequestPool struct {
	client   *Client
	reqPool  sync.Pool
	respPool sync.Pool
}

// NewRequestPool creates a centralized request handling pool
func NewRequestPool(opts *ClientOptions) *RequestPool {
	if opts == nil {
		opts = DefaultOptionsSingleHost() // Use single host optimized settings
	}

	return &RequestPool{
		client: NewClient(opts),
		reqPool: sync.Pool{
			New: func() interface{} { return fasthttp.AcquireRequest() },
		},
		respPool: sync.Pool{
			New: func() interface{} { return fasthttp.AcquireResponse() },
		},
	}
}

// ProcessRequests handles multiple requests efficiently
func (p *RequestPool) ProcessRequests(jobs []payload.PayloadJob) <-chan *ResponseDetails {
	results := make(chan *ResponseDetails)

	go func() {
		defer close(results)

		// Create semaphore for concurrency control
		sem := make(chan struct{}, p.client.options.MaxConnsPerHost)
		var wg sync.WaitGroup

		for _, job := range jobs {
			wg.Add(1)
			sem <- struct{}{} // Acquire semaphore

			go func(job payload.PayloadJob) {
				defer wg.Done()
				defer func() { <-sem }() // Release semaphore

				// Get request/response objects from pool
				req := p.client.AcquireRequest()
				resp := p.client.AcquireResponse()
				defer p.client.ReleaseRequest(req)
				defer p.client.ReleaseResponse(resp)

				// Setup request
				req.SetRequestURI(job.URL)
				req.Header.SetMethod(job.Method)
				req.URI().DisablePathNormalizing = true

				// Set headers
				for _, h := range job.Headers {
					req.Header.Set(h.Header, h.Value)
				}

				// Send request with retry logic
				var err error
				for retries := 0; retries <= p.client.maxRetries; retries++ {
					if err = p.client.DoRaw(req, resp); err == nil {
						break
					}
					time.Sleep(p.client.retryDelay)
				}

				if err != nil {
					logger.LogError("Request error after retries: %v", err)
					return
				}

				results <- p.processResponse(resp, job)
			}(job)
		}

		wg.Wait()
	}()

	return results
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
	URL             string // Added
	BypassMode      string // Added
	CurlCommand     string // Added
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

// // SendRequest handles the complete request cycle using the configured client
// func (c *Client) SendRequest(method, url string, headers map[string]string) (*ResponseDetails, error) {
// 	// Acquire request and response objects from pool
// 	req := c.AcquireRequest()
// 	resp := c.AcquireResponse()
// 	defer c.ReleaseRequest(req)
// 	defer c.ReleaseResponse(resp)

// 	// Setup request
// 	req.SetRequestURI(url)
// 	req.Header.SetMethod(method)
// 	req.URI().DisablePathNormalizing = true
// 	req.Header.DisableNormalizing()
// 	req.Header.SetNoDefaultContentType(true)

// 	// Set headers
// 	for key, value := range headers {
// 		req.Header.Set(key, value)
// 	}

// 	// Perform request with configured client options (including retries)
// 	if err := c.DoRaw(req, resp); err != nil {
// 		return nil, err
// 	}

// 	return c.processResponse(resp, job), nil
// }

// processResponse handles response processing and data extraction
// processResponse converts fasthttp.Response to ResponseDetails
func (p *RequestPool) processResponse(resp *fasthttp.Response, job payload.PayloadJob) *ResponseDetails {
	details := &ResponseDetails{
		URL:         job.URL,
		BypassMode:  job.BypassMode,
		StatusCode:  resp.StatusCode(),
		ContentType: b2s(resp.Header.Peek("Content-Type")),
		ServerInfo:  b2s(resp.Header.Peek("Server")),
		RedirectURL: b2s(resp.Header.Peek("Location")),
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

	// Process body
	body := resp.Body()
	details.ResponseBytes = len(body)

	// Handle body size limits
	if len(body) > DefaultMaxResponseSize {
		details.BodyLimitHit = true
		body = body[:DefaultMaxResponseSize]
	}

	// Create preview
	if len(body) > DefaultBodyPreviewSize {
		details.ResponsePreview = string(body[:DefaultBodyPreviewSize]) + "..."
	} else {
		details.ResponsePreview = string(body)
	}

	// Generate curl command for reproduction
	details.CurlCommand = BuildCurlCommand(job)

	return details
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

// // SetBody sets the request body
// func (r *Request) SetBody(body []byte) {
// 	r.SetBody(body)
// }

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

// s2b converts string to a byte slice without memory allocation.
func s2b(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

// b2s converts byte slice to a string without memory allocation.
// See https://groups.google.com/forum/#!msg/Golang-Nuts/ENgbUzYvCuU/90yGx7GUAgAJ .
func b2s(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// BuildCurlCommand generates a curl command for request reproduction
func BuildCurlCommand(job payload.PayloadJob) string {
	var cmd bytes.Buffer
	cmd.WriteString(fmt.Sprintf("curl -X %s ", job.Method))

	for _, h := range job.Headers {
		cmd.WriteString(fmt.Sprintf("-H '%s: %s' ", h.Header, h.Value))
	}

	cmd.WriteString(fmt.Sprintf("'%s'", job.URL))
	return cmd.String()
}
