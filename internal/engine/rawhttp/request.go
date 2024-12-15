package rawhttp

import (
	"bytes"
	"sync"
	"time"
	"unsafe"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp/bytebufferpool"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/valyala/fasthttp"
)

// RequestPool manages a pool of FastHTTP requests
type RequestPool struct {
	client       *Client
	workerPool   *workerPool
	maxWorkers   int
	payloadQueue chan payload.PayloadJob
	results      chan *RawHTTPResponseDetails
	scanOpts     *ScannerCliOpts
}

type workerPool struct {
	workers []*worker
	ready   chan *worker
	lock    sync.Mutex
	stopCh  chan struct{}
	pool    sync.Pool
}

type worker struct {
	id       int
	client   *Client
	jobs     chan payload.PayloadJob
	results  chan *RawHTTPResponseDetails
	lastUsed time.Time
	builder  *RequestBuilder
}

// RequestBuilder handles the lifecycle of fasthttp requests
type RequestBuilder struct {
	client *Client
}

// ScannerCliOpts reference the cli options
type ScannerCliOpts struct {
	MatchStatusCodes        []int
	ResponseBodyPreviewSize int
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

	maxWorkers := clientOpts.MaxConnsPerHost
	pool := &RequestPool{
		client:       NewClient(clientOpts, errorHandler),
		maxWorkers:   maxWorkers,
		payloadQueue: make(chan payload.PayloadJob, maxWorkers*2),
		results:      make(chan *RawHTTPResponseDetails, maxWorkers*2),
		scanOpts:     scanOpts,
		workerPool: &workerPool{
			ready:  make(chan *worker, maxWorkers),
			stopCh: make(chan struct{}),
		},
	}

	// Initialize worker pool
	pool.workerPool.pool.New = func() interface{} {
		return &worker{
			id:      len(pool.workerPool.workers),
			client:  pool.client,
			jobs:    make(chan payload.PayloadJob, 1),
			results: make(chan *RawHTTPResponseDetails, 1),
			builder: NewRequestBuilder(pool.client),
		}
	}

	// Pre-create workers
	for i := 0; i < maxWorkers; i++ {
		worker := pool.workerPool.pool.Get().(*worker)
		pool.workerPool.workers = append(pool.workerPool.workers, worker)
		pool.workerPool.ready <- worker
	}

	return pool
}

// RequestBuilder handles request construction
func NewRequestBuilder(client *Client) *RequestBuilder {
	return &RequestBuilder{
		client: client,
	}
}

// BuildRequest creates and configures a request from a payload job
func (rb *RequestBuilder) BuildRequest(req *fasthttp.Request, job payload.PayloadJob) {
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

	// Add debug canary/seed
	if logger.IsDebugEnabled() {
		req.Header.Set("X-GB403-Debug", job.PayloadSeed)
	}

	// Set user agent
	if !rb.client.options.NoDefaultUserAgent {
		req.Header.SetUserAgentBytes(rb.client.userAgent)
	}

	// Handle connection settings
	if rb.client.options.ProxyURL != "" {
		req.SetConnectionClose()
	} else if rb.client.options.DisableKeepAlive {
		req.SetConnectionClose()
	} else {
		req.Header.Set("Connection", "keep-alive")
	}
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
	results := make(chan *RawHTTPResponseDetails, len(jobs))

	go func() {
		defer close(results)

		// Use both worker pool limits and connection limits for optimal concurrency
		maxConcurrent := min(p.maxWorkers, p.client.options.MaxConnsPerHost)
		sem := make(chan struct{}, maxConcurrent)
		var wg sync.WaitGroup

		for _, job := range jobs {
			wg.Add(1)
			go func(j payload.PayloadJob) {
				defer wg.Done()

				// Acquire semaphore slot
				sem <- struct{}{}
				defer func() { <-sem }()

				// Get worker from pool
				worker := p.workerPool.acquire()
				if worker == nil {
					logger.LogDebug("Failed to acquire worker for job: %s", j.URL)
					return
				}

				// Process job and release worker
				result := worker.processJob(j)
				p.workerPool.release(worker)

				if result != nil {
					results <- result
				}
			}(job)
		}

		wg.Wait()
	}()

	return results
}

func (w *worker) processJob(job payload.PayloadJob) *RawHTTPResponseDetails {
	// Use FastHTTP's request/response pooling
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Build and send request
	w.builder.BuildRequest(req, job)
	err := w.client.DoRaw(req, resp)
	if err != nil {
		return w.handleError(err, job)
	}

	return w.processResponse(resp, job)
}

func (w *worker) handleError(err error, job payload.PayloadJob) *RawHTTPResponseDetails {
	if logger.IsDebugEnabled() {
		logger.LogDebug("Error processing job %s: %v", job.URL, err)
	}
	return nil
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

// processResponse handles response processing
func (w *worker) processResponse(resp *fasthttp.Response, job payload.PayloadJob) *RawHTTPResponseDetails {
	result := &RawHTTPResponseDetails{
		URL:        append([]byte(nil), job.URL...),
		BypassMode: append([]byte(nil), job.PayloadSeed...),
		StatusCode: resp.StatusCode(),
	}

	// Process headers
	headerBuf := bytebufferpool.Get()
	defer bytebufferpool.Put(headerBuf)

	resp.Header.VisitAll(func(key, value []byte) {
		headerBuf.WriteString(Byte2String(key))
		headerBuf.WriteString(": ")
		headerBuf.WriteString(Byte2String(value))
		headerBuf.WriteString("\n")

		switch string(key) {
		case "Content-Type":
			result.ContentType = append([]byte(nil), value...)
		case "Server":
			result.ServerInfo = append([]byte(nil), value...)
		case "Location":
			result.RedirectURL = append([]byte(nil), value...)
		}
	})

	result.ResponseHeaders = append([]byte(nil), headerBuf.B...)

	// Process body
	result.ContentLength = int64(resp.Header.ContentLength())
	result.ResponseBytes = len(resp.Body())

	// Get response preview if configured
	if w.client.options.ResponseBodyPreviewSize > 0 {
		previewSize := min(len(resp.Body()), w.client.options.ResponseBodyPreviewSize)
		result.ResponsePreview = append([]byte(nil), resp.Body()[:previewSize]...)
	}

	// Extract title if present
	result.Title = extractTitle(resp.Body())

	// Generate curl command for reproduction
	result.CurlCommand = w.builder.GenerateCurlCommand(job)

	return result
}

// WorkerPool methods
func (wp *workerPool) acquire() *worker {
	select {
	case worker := <-wp.ready:
		worker.lastUsed = time.Now()
		return worker
	default:
		// If no workers available, try to create new one
		wp.lock.Lock()
		defer wp.lock.Unlock()

		if len(wp.workers) < cap(wp.ready) {
			worker := wp.pool.Get().(*worker)
			wp.workers = append(wp.workers, worker)
			worker.lastUsed = time.Now()
			return worker
		}

		// Wait for available worker
		select {
		case worker := <-wp.ready:
			worker.lastUsed = time.Now()
			return worker
		case <-time.After(5 * time.Second):
			return nil
		}
	}
}

func (wp *workerPool) release(w *worker) {
	w.lastUsed = time.Now()
	select {
	case wp.ready <- w:
		// Worker successfully returned to pool
	default:
		// Pool is full, clean up worker
		wp.lock.Lock()
		for i, worker := range wp.workers {
			if worker == w {
				wp.workers[i] = wp.workers[len(wp.workers)-1]
				wp.workers = wp.workers[:len(wp.workers)-1]
				break
			}
		}
		wp.lock.Unlock()
		wp.pool.Put(w)
	}
}

func (wp *workerPool) cleanIdleWorkers(maxIdleTime time.Duration) {
	threshold := time.Now().Add(-maxIdleTime)
	wp.lock.Lock()
	defer wp.lock.Unlock()

	activeWorkers := make([]*worker, 0, len(wp.workers))
	for _, w := range wp.workers {
		if w.lastUsed.After(threshold) {
			activeWorkers = append(activeWorkers, w)
		} else {
			// Return to sync.Pool for potential reuse
			wp.pool.Put(w)
		}
	}
	wp.workers = activeWorkers
}

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// String2Byte converts string to a byte slice without memory allocation.
// This conversion *does not* copy data. Note that casting via "([]byte)(string)" *does* copy data.
// Also note that you *should not* change the byte slice after conversion, because Go strings
// are treated as immutable. This would cause a segmentation violation panic.
func String2Byte(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

// Byte2String converts byte slice to a string without memory allocation.
// This conversion *does not* copy data. Note that casting via "(string)([]byte)" *does* copy data.
// Also note that you *should not* change the byte slice after conversion, because Go strings
// are treated as immutable. This would cause a segmentation violation panic.
func Byte2String(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// BuildCurlCommand generates a curl poc command to reproduce the findings
// Uses a local bytebufferpool implementation from this project
func (rb *RequestBuilder) GenerateCurlCommand(job payload.PayloadJob) []byte {
	var buf bytebufferpool.ByteBuffer
	defer buf.Reset()

	buf.WriteString("curl -X ")
	buf.WriteString(job.Method)
	buf.WriteString(" '")
	buf.WriteString(job.URL)
	buf.WriteString("'")

	for _, h := range job.Headers {
		buf.WriteString(" -H '")
		buf.WriteString(h.Header)
		buf.WriteString(": ")
		buf.WriteString(h.Value)
		buf.WriteString("'")
	}

	return append([]byte(nil), buf.B...)
}

// Helper function to extract title from HTML
func extractTitle(body []byte) []byte {
	lower := bytes.ToLower(body)
	titleStart := bytes.Index(lower, []byte("<title>"))
	if titleStart == -1 {
		return nil
	}
	titleStart += 7 // len("<title>")

	titleEnd := bytes.Index(lower[titleStart:], []byte("</title>"))
	if titleEnd == -1 {
		return nil
	}

	return append([]byte(nil), body[titleStart:titleStart+titleEnd]...)
}
