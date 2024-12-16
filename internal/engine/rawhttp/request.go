package rawhttp

import (
	"bytes"
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

// RequestPool manages a pool of FastHTTP requests
type RequestPool struct {
	client       *Client
	workerPool   *workerPool
	maxWorkers   int
	payloadQueue chan payload.PayloadJob
	results      chan *RawHTTPResponseDetails
	scanOpts     *ScannerCliOpts
	errorHandler *GB403ErrorHandler.ErrorHandler
}

type workerPool struct {
	workers []*worker
	ready   chan *worker
	lock    sync.Mutex
	stopCh  chan struct{}
	pool    sync.Pool
}

type worker struct {
	id           int
	client       *Client
	jobs         chan payload.PayloadJob
	results      chan *RawHTTPResponseDetails
	lastUsed     time.Time
	builder      *RequestBuilder
	scanOpts     *ScannerCliOpts
	errorHandler *GB403ErrorHandler.ErrorHandler
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
		errorHandler: errorHandler,
		workerPool: &workerPool{
			ready:  make(chan *worker, maxWorkers),
			stopCh: make(chan struct{}),
		},
	}

	// Initialize worker pool
	pool.workerPool.pool.New = func() interface{} {
		return &worker{
			id:           len(pool.workerPool.workers),
			client:       pool.client,
			jobs:         make(chan payload.PayloadJob, 1),
			results:      make(chan *RawHTTPResponseDetails, 1),
			builder:      NewRequestBuilder(pool.client),
			scanOpts:     scanOpts,
			errorHandler: pool.errorHandler,
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
		req.Header.SetUserAgentBytes(CustomUserAgent)
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

// ProcessRequests handles multiple requests "efficiently"
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
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	w.builder.BuildRequest(req, job)
	if err := w.client.DoRaw(req, resp); err != nil {
		if err := w.errorHandler.HandleError(err, GB403ErrorHandler.ErrorContext{
			TargetURL:   []byte(job.URL),
			ErrorSource: []byte("Worker.processJob"),
			BypassMode:  []byte(job.BypassMode),
		}); err == nil { // <-- Check for nil to continue processing
			return w.processResponse(resp, job)
		}
		logger.LogError("Request failed: %v", err)
		return nil
	}

	return w.processResponse(resp, job)
}

// processResponse handles response processing
func (w *worker) processResponse(resp *fasthttp.Response, job payload.PayloadJob) *RawHTTPResponseDetails {
	result := &RawHTTPResponseDetails{
		URL:        append([]byte(nil), job.URL...),
		BypassMode: append([]byte(nil), job.PayloadSeed...),
		StatusCode: resp.StatusCode(),
	}

	// Get header buffer from pool
	headerBuf := bytebufferpool.Get()
	defer bytebufferpool.Put(headerBuf)

	// Write status line
	headerBuf.Write(resp.Header.Protocol())
	headerBuf.WriteByte(' ')
	headerBuf.B = fasthttp.AppendUint(headerBuf.B, resp.StatusCode())
	headerBuf.WriteByte(' ')
	headerBuf.Write(resp.Header.StatusMessage())
	headerBuf.WriteString("\r\n")

	// Process headers once
	resp.Header.VisitAll(func(key, value []byte) {
		headerBuf.Write(key)
		headerBuf.WriteString(": ")
		headerBuf.Write(value)
		headerBuf.WriteString("\r\n")
	})
	headerBuf.WriteString("\r\n")

	// Store headers
	result.ResponseHeaders = append([]byte(nil), headerBuf.B...)

	// Use direct header access methods
	result.ContentType = append([]byte(nil), resp.Header.ContentType()...)
	result.ServerInfo = append([]byte(nil), resp.Header.Server()...)
	if location := resp.Header.PeekBytes([]byte("Location")); len(location) > 0 {
		result.RedirectURL = append([]byte(nil), location...)
	}

	// Process body - get it once
	body := resp.Body()
	result.ContentLength = int64(resp.Header.ContentLength())
	result.ResponseBytes = len(body)

	// Get preview if configured
	if w.scanOpts.ResponseBodyPreviewSize > 0 && len(body) > 0 {
		previewSize := min(len(body), w.scanOpts.ResponseBodyPreviewSize)
		result.ResponsePreview = append([]byte(nil), body[:previewSize]...)
	}

	// Extract title if needed
	if bytes.Contains(result.ContentType, []byte("html")) {
		result.Title = extractTitle(body)
	}

	// Generate curl command
	result.CurlCommand = BuildCurlCommandPoc(job)

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

func (p *RequestPool) Close() {
	close(p.workerPool.stopCh)

	// Clean up workers
	p.workerPool.lock.Lock()
	for _, w := range p.workerPool.workers {
		close(w.jobs)
		close(w.results)
	}
	p.workerPool.workers = nil
	p.workerPool.lock.Unlock()

	// Clean up channels
	close(p.payloadQueue)
	close(p.results)
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

// BuildCurlCommandPoc generates a curl poc command to reproduce the findings
// Uses a local bytebufferpool implementation from this project
func BuildCurlCommandPoc(job payload.PayloadJob) []byte {
	bb := bytebufferpool.Get()
	defer bytebufferpool.Put(bb)

	if runtime.GOOS == "windows" {
		bb.WriteString("curl.exe")
	} else {
		bb.WriteString("curl")
	}

	bb.WriteString(" -skgi --path-as-is")

	// Add method only if not GET
	if job.Method != "GET" {
		bb.WriteString(" -X ")
		bb.WriteString(job.Method)
	}

	// Add headers before URL
	for _, h := range job.Headers {
		bb.WriteString(" -H '")
		bb.WriteString(h.Header)
		bb.WriteString(": ")
		bb.WriteString(h.Value)
		bb.WriteString("'")
	}

	// last is URL
	bb.WriteString(" '")
	bb.WriteString(job.URL)
	bb.WriteString("'")

	return append([]byte(nil), bb.B...)
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
