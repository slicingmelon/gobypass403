package rawhttp

import (
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp/bytebufferpool"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
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
	URL             []byte
	BypassMode      []byte
	CurlCommand     []byte
	StatusCode      int
	ResponsePreview []byte
	ResponseHeaders []byte
	ContentType     []byte
	ContentLength   int64
	ServerInfo      []byte
	RedirectURL     []byte
	ResponseBytes   int
	Title           []byte
}

func NewRequestPool(clientOpts *ClientOptions, scanOpts *ScannerCliOpts, errorHandler *GB403ErrorHandler.ErrorHandler) *RequestPool {
	if clientOpts == nil {
		clientOpts = DefaultOptionsSameHost()
	}

	pool := &RequestPool{
		client:   NewClient(clientOpts, errorHandler),
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

	// Handle connection settings
	if rb.client.options.ProxyURL != "" {
		// Always use Connection: close with proxy
		req.SetConnectionClose()
	} else if rb.client.options.DisableKeepAlive {
		req.SetConnectionClose()
	} else {
		req.Header.Set("Connection", "keep-alive")
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
	// Reduce buffer size to prevent too many concurrent connections
	bufferSize := min(len(jobs), p.client.options.MaxConnsPerHost/2)
	results := make(chan *RawHTTPResponseDetails, bufferSize)

	go func() {
		defer close(results)

		// Use a smaller number of concurrent requests
		maxConcurrent := min(p.client.options.MaxConnsPerHost/2, 10)
		sem := make(chan struct{}, maxConcurrent)
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

		// Log before sending
		if logger.IsDebugEnabled() {
			logger.LogDebug("[%s] [Canary: %s] Preparing request: %s",
				job.BypassMode,
				job.PayloadSeed,
				job.URL)
		}

		// Execute
		resp, err := builder.SendRequest(req)

		// Always release request immediately after use
		fasthttp.ReleaseRequest(req)

		if err != nil {
			handleError(job, err, ch)
			continue
		}

		// Log successful request
		logger.LogVerbose("[%s] Request sent successfully: %s", job.BypassMode, job.URL)

		// Process response before releasing it
		result := wp.pool.ProcessResponse(resp, job)

		// Release response immediately after processing
		fasthttp.ReleaseResponse(resp)

		// Send result only after response is fully processed and released
		ch.results <- result
	}
}

func handleError(job payload.PayloadJob, err error, ch *workerChan) {
	if logger.IsDebugEnabled() {
		logger.LogError("[%s] [Canary: %s] Request error for %s: %v",
			job.BypassMode,
			job.PayloadSeed,
			job.URL,
			err)
	}

	if logger.IsVerboseEnabled() {
		logger.LogError("[%s] Request error for %s: %v",
			job.BypassMode,
			job.URL,
			err)
	}

	ch.results <- nil
	time.Sleep(100 * time.Millisecond)
}

func (wp *workerPool) release(ch *workerChan) {
	wp.lock.Lock()
	wp.ready = append(wp.ready, ch)
	wp.lock.Unlock()
}

// processResponse handles response processing
func (p *RequestPool) ProcessResponse(resp *fasthttp.Response, job payload.PayloadJob) *RawHTTPResponseDetails {
	details := &RawHTTPResponseDetails{
		URL:        String2Byte(job.URL),
		BypassMode: String2Byte(job.BypassMode),
		StatusCode: resp.StatusCode(),
	}

	headerBuf := bytebufferpool.Get()
	defer bytebufferpool.Put(headerBuf)

	// Use protocol (http version from the response)
	headerBuf.Write(resp.Header.Protocol())
	headerBuf.WriteByte(' ')
	headerBuf.B = fasthttp.AppendUint(headerBuf.B, resp.StatusCode())
	headerBuf.WriteByte(' ')
	headerBuf.Write(resp.Header.StatusMessage())
	headerBuf.WriteString("\r\n")

	// Write headers
	resp.Header.VisitAll(func(key, value []byte) {
		headerBuf.Write(key)
		headerBuf.WriteString(": ")
		headerBuf.Write(value)
		headerBuf.Write([]byte("\r\n"))
	})
	headerBuf.WriteString("\r\n")

	details.ResponseHeaders = append([]byte(nil), headerBuf.B...)

	// Use direct byte access for headers
	details.ContentType = append([]byte(nil), resp.Header.ContentType()...)
	details.ServerInfo = append([]byte(nil), resp.Header.Server()...)
	if location := resp.Header.PeekBytes([]byte("Location")); len(location) > 0 {
		details.RedirectURL = append([]byte(nil), location...)
	}

	// Process body
	body := resp.Body()
	if len(body) > p.scanOpts.ResponseBodyPreviewSize {
		details.ResponsePreview = append([]byte(nil), body[:p.scanOpts.ResponseBodyPreviewSize]...)
	} else {
		details.ResponsePreview = append([]byte(nil), body...)
	}
	details.ResponseBytes = len(body)
	details.ContentLength = int64(resp.Header.ContentLength())

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

// BuildCurlCommand generates a curl poc command to reproduce the findings
// Uses a local bytebufferpool implementation from this project
func BuildCurlCmd(job payload.PayloadJob) []byte {
	buf := bytebufferpool.Get()
	defer bytebufferpool.Put(buf)

	if runtime.GOOS == "windows" {
		buf.WriteString("curl.exe")
	} else {
		buf.WriteString("curl")
	}
	buf.WriteString(" -skgi --path-as-is")

	if job.Method != "GET" {
		buf.WriteString(" -X ")
		buf.WriteString(job.Method)
	}

	for _, h := range job.Headers {
		buf.WriteString(" -H '")
		buf.WriteString(h.Header)
		buf.WriteString(": ")
		buf.WriteString(h.Value)
		buf.WriteString("'")
	}

	buf.WriteString(" '")
	buf.WriteString(job.URL)
	buf.WriteString("'")

	return append([]byte(nil), buf.B...)
}
