package rawhttp

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/valyala/fasthttp"
)

// RequestBuilder handles the lifecycle of fasthttp requests
type RequestBuilder struct {
	client *Client
}

type Header struct {
	Key   string
	Value string
}

// ScanOptions reference the cli options, we'll need them internally here as well
type ScannerCliOpts struct {
	MatchStatusCodes        []int
	ResponseBodyPreviewSize int
}

// RequestPool manages a pool of FastHTTP requests
type RequestPool struct {
	client     *Client
	workerPool *workerPool
	jobs       []payload.PayloadJob // worker pool jobs
	scanOpts   *ScannerCliOpts      // Direct reference to (some) scanner options
}

type workerPool struct {
	workersCount    int
	maxWorkersCount int
	ready           []*workerChan
	lock            sync.Mutex
	stopCh          chan struct{}
	workerChanPool  sync.Pool
	pool            *RequestPool
}

type workerChan struct {
	lastUseTime time.Time
	jobs        chan payload.PayloadJob
	results     chan *RawHTTPResponseDetails
}

// ResponseDetails contains processed response information
type RawHTTPResponseDetails struct {
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
}

func NewRequestPool(clientOpts *ClientOptions, scanOpts *ScannerCliOpts) *RequestPool {
	if clientOpts == nil {
		clientOpts = DefaultOptionsSingleHost()
	}

	pool := &RequestPool{
		client:   NewClient(clientOpts),
		scanOpts: scanOpts,
		workerPool: &workerPool{
			maxWorkersCount: clientOpts.MaxConnsPerHost,
			stopCh:          make(chan struct{}),
		},
	}

	pool.workerPool.pool = pool
	pool.workerPool.workerChanPool.New = func() interface{} {
		return &workerChan{
			jobs:    make(chan payload.PayloadJob, 1),
			results: make(chan *RawHTTPResponseDetails, 1),
		}
	}

	return pool
}

// NewRequestBuilder creates a new request builder
func NewRequestBuilder(client *Client) *RequestBuilder {
	return &RequestBuilder{
		client: client,
	}
}

// BuildRequest creates and configures a request from a payload job
func (rb *RequestBuilder) BuildRequest(job payload.PayloadJob) *fasthttp.Request {
	req := fasthttp.AcquireRequest()

	// Core request setup
	req.SetRequestURI(job.URL)
	req.Header.SetMethod(job.Method)

	// Disable normalizing for raw path testing
	req.URI().DisablePathNormalizing = true
	req.Header.DisableNormalizing()
	req.Header.SetNoDefaultContentType(true)

	// Add payload headers
	for _, h := range job.Headers {
		req.Header.Set(h.Header, h.Value)
	}

	// add debug canary/seed to each request for better debugging
	if logger.IsDebugEnabled() {
		req.Header.Set("X-GB403-Debug", job.PayloadSeed)
	}

	// set a decent user agent
	if !rb.client.options.NoDefaultUserAgent {
		req.Header.SetUserAgentBytes(rb.client.userAgent)
	}

	if rb.client.options.DisableKeepAlive {
		req.SetConnectionClose()
	}

	return req
}

// SendRequest performs the request and returns a response
func (rb *RequestBuilder) SendRequest(req *fasthttp.Request) (*fasthttp.Response, error) {
	resp := fasthttp.AcquireResponse()

	err := rb.client.DoRaw(req, resp)
	if err != nil {
		fasthttp.ReleaseResponse(resp)
		return nil, err
	}

	return resp, nil
}

// ProcessRequests handles multiple requests efficiently
func (p *RequestPool) ProcessRequests(jobs []payload.PayloadJob) <-chan *RawHTTPResponseDetails {
	// Buffer size based on number of jobs, capped at a reasonable maximum
	bufferSize := min(len(jobs), p.client.options.MaxConnsPerHost)
	results := make(chan *RawHTTPResponseDetails, bufferSize)

	go func() {
		defer close(results)

		// Use the configured thread count from scanner options
		sem := make(chan struct{}, p.client.options.MaxConnsPerHost)
		var wg sync.WaitGroup

		for _, job := range jobs {
			wg.Add(1)
			go func(j payload.PayloadJob) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				workerChan := p.workerPool.getCh()
				if workerChan == nil {
					return
				}

				workerChan.jobs <- j
				result := <-workerChan.results
				if result != nil {
					results <- result
				}
				p.workerPool.release(workerChan)
			}(job)
		}

		wg.Wait()
	}()

	return results
}

func (wp *workerPool) getCh() *workerChan {
	wp.lock.Lock()
	defer wp.lock.Unlock()

	// Try to get existing worker
	if len(wp.ready) > 0 {
		ch := wp.ready[len(wp.ready)-1]
		wp.ready = wp.ready[:len(wp.ready)-1]
		return ch
	}

	// Create new worker if possible
	if wp.workersCount < wp.maxWorkersCount {
		wp.workersCount++
		ch := wp.workerChanPool.Get().(*workerChan)

		// Start worker goroutine
		go wp.workerFunc(ch)

		return ch
	}

	return nil
}

func (wp *workerPool) workerFunc(ch *workerChan) {
	builder := NewRequestBuilder(wp.pool.client)

	for job := range ch.jobs {
		// Build request
		req := builder.BuildRequest(job)

		// Execute
		resp, err := builder.SendRequest(req)

		// Always release request
		fasthttp.ReleaseRequest(req)

		if err != nil {
			logger.LogVerbose("Request error: %v", err)
			ch.results <- nil
			continue
		}

		// Process response
		result := wp.pool.processResponse(resp, job)

		// Release response
		fasthttp.ReleaseResponse(resp)

		ch.results <- result
	}
}

func (wp *workerPool) release(ch *workerChan) {
	wp.lock.Lock()
	wp.ready = append(wp.ready, ch)
	wp.lock.Unlock()
}

// processResponse handles response processing and data extraction
// processResponse converts fasthttp.Response to ResponseDetails
func (p *RequestPool) processResponse(resp *fasthttp.Response, job payload.PayloadJob) *RawHTTPResponseDetails {
	details := &RawHTTPResponseDetails{
		URL:         job.URL,
		BypassMode:  job.BypassMode,
		StatusCode:  resp.StatusCode(),
		ContentType: Byte2String(resp.Header.ContentType()),
		ServerInfo:  string(resp.Header.Server()),
		RedirectURL: Byte2String(resp.Header.Peek("Location")),
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

	// Just read what we got in the buffer
	body := resp.Body()

	// even a half of the resp body buffer is enough, we can use it as a preview
	if len(body) > p.scanOpts.ResponseBodyPreviewSize {
		body = body[:p.scanOpts.ResponseBodyPreviewSize]
	}

	details.ResponsePreview = string(body)
	details.ResponseBytes = len(body)

	// ContentLength returns Content-Length header value.
	// It may be negative: -1 means Transfer-Encoding: chunked. -2 means Transfer-Encoding: identity.
	if resp.Header.ContentLength() > 0 {
		details.ContentLength = int64(resp.Header.ContentLength())
	}

	details.CurlCommand = BuildCurlCmd(job)
	return details
}

// s2b converts string to a byte slice without memory allocation.
// This conversion *does not* copy data. Note that casting via "([]byte)(string)" *does* copy data.
// Also note that you *should not* change the byte slice after conversion, because Go strings
// are treated as immutable. This would cause a segmentation violation panic.
func String2Byte(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

// b2s converts byte slice to a string without memory allocation.
// See https://groups.google.com/forum/#!msg/Golang-Nuts/ENgbUzYvCuU/90yGx7GUAgAJ .
// This conversion *does not* copy data. Note that casting via "(string)([]byte)" *does* copy data.
// Also note that you *should not* change the byte slice after conversion, because Go strings
// are treated as immutable. This would cause a segmentation violation panic.
func Byte2String(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// BuildCurlCommand generates a curl command for request reproduction
func BuildCurlCmd(job payload.PayloadJob) string {
	// Determine curl command based on OS
	curlCmd := "curl"
	if runtime.GOOS == "windows" {
		curlCmd = "curl.exe"
	}

	parts := []string{curlCmd, "-skgi", "--path-as-is"}

	// Add method if not GET
	if job.Method != "GET" {
		parts = append(parts, "-X", job.Method)
	}

	// Convert job.Headers to map for consistent ordering
	headers := make(map[string]string)
	for _, h := range job.Headers {
		headers[h.Header] = h.Value
	}

	// Add headers
	for k, v := range headers {
		parts = append(parts, fmt.Sprintf("-H '%s: %s'", k, v))
	}

	// Add URL
	parts = append(parts, fmt.Sprintf("'%s'", job.URL))

	return strings.Join(parts, " ")
}
