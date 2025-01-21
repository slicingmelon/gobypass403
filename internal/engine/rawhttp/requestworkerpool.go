package rawhttp

import (
	"bytes"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/valyala/fasthttp"
)

// RequestPool2 manages the entire request processing lifecycle
type RequestPool2 struct {
	// Core components
	client       *HttpClient
	errorHandler *GB403ErrorHandler.ErrorHandler

	// Atomic counters
	workersCount  atomic.Int32
	activeWorkers atomic.Int32
	stopped       atomic.Bool

	// Worker management
	workerChanPool sync.Pool     // Pool of reusable worker channels
	ready          []*workerChan // Slice of available workers
	maxWorkers     int32

	// Synchronization
	mu sync.Mutex

	// Channels
	results chan *RawHTTPResponseDetails
	stopCh  chan struct{}
}

// workerChan represents a worker's job channel and metadata
type workerChan struct {
	ch          chan payload.PayloadJob // Channel for receiving jobs
	lastUseTime time.Time               // Last time this worker was used
}

func NewRequestPool2(opts *HttpClientOptions, scanOpts *ScannerCliOpts, errorHandler *GB403ErrorHandler.ErrorHandler) *RequestPool2 {
	queueSize := scanOpts.MaxWorkers * 2

	pool := &RequestPool2{
		client:       NewHTTPClient(opts, errorHandler),
		errorHandler: errorHandler,
		results:      make(chan *RawHTTPResponseDetails, queueSize),
		stopCh:       make(chan struct{}),

		// Worker management
		workerChanPool: sync.Pool{
			New: func() any {
				return &workerChan{
					ch: make(chan payload.PayloadJob, 1),
				}
			},
		},
		ready: make([]*workerChan, 0, scanOpts.MaxWorkers),
	}

	// Initialize atomic counters
	pool.workersCount.Store(0)
	pool.activeWorkers.Store(0)
	pool.stopped.Store(false)

	// Start cleanup goroutine
	go pool.cleanupWorkers()

	return pool
}

// ProcessRequests handles a batch of jobs
func (p *RequestPool2) ProcessRequests(jobs []payload.PayloadJob) <-chan *RawHTTPResponseDetails {
	p.queuedTasks.Add(int32(len(jobs)))

	go func() {
		defer close(p.results)

		for _, job := range jobs {
			RequestWorker2 := p.getWorker()
			RequestWorker2.taskChan <- job
		}
	}()

	return p.results
}

// getWorker returns an available RequestWorker2 or creates a new one
// getWorker returns an available worker or creates a new one
func (p *RequestPool2) getWorker() *RequestWorker2 {
	// Try quick access workers first
	if worker := p.idleWorker1; worker != nil &&
		atomic.CompareAndSwapPointer((*unsafe.Pointer)(unsafe.Pointer(&p.idleWorker1)),
			unsafe.Pointer(worker), nil) {
		return worker
	}

	if worker := p.idleWorker2; worker != nil &&
		atomic.CompareAndSwapPointer((*unsafe.Pointer)(unsafe.Pointer(&p.idleWorker2)),
			unsafe.Pointer(worker), nil) {
		return worker
	}

	// Then check idle worker list
	p.mu.Lock()
	if len(p.idleWorkers) > 0 {
		worker := p.idleWorkers[len(p.idleWorkers)-1]
		p.idleWorkers = p.idleWorkers[:len(p.idleWorkers)-1]
		p.mu.Unlock()
		return worker
	}
	p.mu.Unlock()

	// Create new if under limit
	if p.activeWorkers.Load() < p.maxWorkers {
		return p.createWorker()
	}

	// Wait for available worker
	return p.waitForWorker()
}

func (p *RequestPool2) waitForWorker() *RequestWorker2 {
	for !p.stopped.Load() {
		if worker := p.getWorker(); worker != nil {
			return worker
		}
		runtime.Gosched() // Just yield CPU, no sleep
	}
	return nil
}

func (p *RequestPool2) createWorker() *RequestWorker2 {
	w := p.workerCache.Get().(*RequestWorker2)
	w.pool = p
	w.id = p.activeWorkers.Add(1)

	p.mu.Lock()
	p.workers = append(p.workers, w)
	p.mu.Unlock()

	// Start RequestWorker2 goroutine
	go w.run()

	return w
}

// BuildRequest constructs the HTTP request
func (rb *RequestBuilder) BuildRequest(req *fasthttp.Request, job payload.PayloadJob) error {
	req.UseHostHeader = false
	req.Header.SetMethod(job.Method)

	// Set the raw URI for the first line of the request
	req.SetRequestURI(job.FullURL)

	// Disable all normalizing for raw path testing
	req.URI().DisablePathNormalizing = true
	req.Header.DisableNormalizing()
	req.Header.SetNoDefaultContentType(true)

	// !!Always close connection when custom headers are present
	shouldCloseConn := len(job.Headers) > 0 ||
		rb.Client.options.DisableKeepAlive ||
		rb.Client.options.ProxyURL != ""

	// Set headers directly
	for _, h := range job.Headers {
		if h.Header == "Host" {
			req.UseHostHeader = true
			shouldCloseConn = true
		}
		req.Header.Set(h.Header, h.Value)
	}

	// Set standard headers
	req.Header.SetUserAgentBytes(CustomUserAgent)

	if GB403Logger.IsDebugEnabled() {
		req.Header.Set("X-GB403-Token", job.PayloadToken)
	}

	// Handle connection settings
	if shouldCloseConn {
		req.SetConnectionClose()
	} else {
		//req.Header.Set("Connection", "keep-alive")
		req.SetConnectionClose()
	}

	return nil
}

// SendRequestJob handles the actual HTTP request
func (p *RequestPool2) ProcessRequests(jobs []payload.PayloadJob) <-chan *RawHTTPResponseDetails {
	err := w.pool.client.DoRequest(req, resp)
	if err != nil {
		return w.pool.errorHandler.HandleError(err, GB403ErrorHandler.ErrorContext{
			Host:         []byte(job.Host),
			ErrorSource:  []byte("RequestWorker.SendRequestJob"),
			BypassModule: []byte(job.BypassModule),
		})
	}
	return nil
}

func (w *RequestWorker2) ProcessResponseJob(resp *fasthttp.Response, job payload.PayloadJob) *RawHTTPResponseDetails {
	// Get values that are used multiple times
	statusCode := resp.StatusCode()
	body := resp.Body()
	contentLength := resp.Header.ContentLength()

	result := &RawHTTPResponseDetails{
		URL:           append([]byte(nil), job.FullURL...),
		BypassModule:  append([]byte(nil), job.BypassModule...),
		StatusCode:    statusCode,
		ContentLength: int64(contentLength),
		ResponseBytes: len(body),
	}

	// Check for redirect early
	if fasthttp.StatusCodeIsRedirect(statusCode) {
		if location := PeekHeaderKeyCaseInsensitive(&resp.Header, []byte("Location")); len(location) > 0 {
			result.RedirectURL = append([]byte(nil), location...)
		}
	}

	// Create header buffer
	headerBuf := headerBufPool.Get()
	defer headerBufPool.Put(headerBuf)
	headerBuf.Reset()

	// Write status line
	headerBuf.Write(resp.Header.Protocol())
	headerBuf.Write(strSpace)
	headerBuf.B = fasthttp.AppendUint(headerBuf.B, statusCode)
	headerBuf.Write(strSpace)
	headerBuf.Write(resp.Header.StatusMessage())
	headerBuf.Write(strCRLF)

	// Process headers
	resp.Header.VisitAll(func(key, value []byte) {
		headerBuf.Write(key)
		headerBuf.Write(strColonSpace)
		headerBuf.Write(value)
		headerBuf.Write(strCRLF)
	})
	headerBuf.Write(strCRLF)

	// Store processed data
	result.ResponseHeaders = append([]byte(nil), headerBuf.B...)
	result.ContentType = append([]byte(nil), resp.Header.ContentType()...)
	result.ServerInfo = append([]byte(nil), resp.Header.Server()...)

	// Handle body preview using client options
	previewSize := w.pool.client.options.ResponseBodyPreviewSize
	if previewSize > 0 && len(body) > 0 {
		if len(body) > previewSize {
			result.ResponsePreview = append([]byte(nil), body[:previewSize]...)
		} else {
			result.ResponsePreview = append([]byte(nil), body...)
		}
	}

	// Extract title if HTML
	if bytes.Contains(result.ContentType, strHTML) {
		result.Title = extractTitle(body)
	}

	// Generate curl command PoC
	result.CurlCommand = BuildCurlCommandPoc(job)

	return result
}

// Worker's main loop
func (w *RequestWorker2) run() {
	builder := &RequestBuilder{Client: w.pool.client}

	for job := range w.taskChan {
		resp := w.pool.client.AcquireResponse()
		req := w.pool.client.AcquireRequest()

		// Build request
		if err := builder.BuildRequest(req, job); err != nil {
			w.pool.errorHandler.HandleError(err, GB403ErrorHandler.ErrorContext{
				ErrorSource:  []byte("RequestWorker.BuildRequest"),
				Host:         []byte(job.Host),
				BypassModule: []byte(job.BypassModule),
			})
			continue
		}

		// Send request with job context
		if err := w.SendRequestJob(req, resp, job); err != nil {
			continue
		}

		// Process response with job context
		result := w.ProcessResponseJob(resp, job)
		w.pool.results <- result

		// Cleanup
		w.pool.client.ReleaseRequest(req)
		w.pool.client.ReleaseResponse(resp)

		// Mark as idle
		w.lastUsed = time.Now()
		w.isIdle = true
		w.pool.queuedTasks.Add(-1)
	}
}

// Cleanup idle workers periodically
func (p *RequestPool2) cleanupIdleWorkers() {
	ticker := time.NewTicker(p.idleTimeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.removeIdleWorkers()
		}
	}
}

func (p *RequestPool2) removeIdleWorkers() {
	p.mu.Lock()
	defer p.mu.Unlock()

	deadline := time.Now().Add(-p.idleTimeout)
	active := make([]*RequestWorker2, 0, len(p.workers))

	for _, w := range p.workers {
		if w.isIdle && w.lastUsed.Before(deadline) {
			close(w.taskChan)
			p.workerCache.Put(w)
			p.activeWorkers.Add(-1)
		} else {
			active = append(active, w)
		}
	}

	p.workers = active
}

func (p *RequestPool2) Close() {
	if !p.stopped.CompareAndSwap(false, true) {
		return
	}

	p.mu.Lock()
	for _, worker := range p.workers {
		close(worker.taskChan)
	}
	p.workers = nil
	p.mu.Unlock()

	if p.client != nil {
		p.client.Close()
	}
}
