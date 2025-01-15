package rawhttp

import (
	"bytes"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/bytesutil"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/valyala/fasthttp"
)

var curlCmd []byte

func init() {
	if runtime.GOOS == "windows" {
		curlCmd = bytesutil.ToUnsafeBytes("curl.exe")
	} else {
		curlCmd = bytesutil.ToUnsafeBytes("curl")
	}
}

// RequestPool manages a pool of FastHTTP requests
type RequestPool struct {
	client       *HttpClient
	workerPool   *requestWorkerPool
	maxWorkers   int
	payloadQueue chan payload.PayloadJob
	results      chan *RawHTTPResponseDetails
	scanOpts     *ScannerCliOpts
	errorHandler *GB403ErrorHandler.ErrorHandler
	closeMu      sync.Once
}

// ConnPoolStrategyType define strategy of connection pool enqueue/dequeue.
type ConnPoolStrategyType int

const (
	FIFO ConnPoolStrategyType = iota
	LIFO
)

type requestWorkerPool struct {
	workers       []*requestWorker
	ready         chan *requestWorker
	lock          sync.Mutex
	stopCh        chan struct{}
	pool          sync.Pool
	activeWorkers atomic.Int32
	queuedJobs    atomic.Int32

	// news
	maxIdleWorkerDuration time.Duration
	lastCleanup           time.Time
	strategy              ConnPoolStrategyType // FIFO or LIFO
}

type requestWorker struct {
	id           int
	client       *HttpClient
	jobs         chan payload.PayloadJob
	results      chan *RawHTTPResponseDetails
	lastUsed     time.Time
	builder      *RequestBuilder
	scanOpts     *ScannerCliOpts
	errorHandler *GB403ErrorHandler.ErrorHandler
	pool         *requestWorkerPool
}

type ProgressTracker interface {
	UpdateWorkerStats(moduleName string, totalWorkers int64)
}

// RequestBuilder handles the lifecycle of fasthttp requests
type RequestBuilder struct {
	client *HttpClient
}

// ScannerCliOpts reference the cli options
type ScannerCliOpts struct {
	MatchStatusCodes        []int
	ResponseBodyPreviewSize int
	ModuleName              string
}

// ResponseDetails contains processed response information
type RawHTTPResponseDetails struct {
	URL             []byte
	BypassModule    []byte
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
	// Just use the options as provided, with a fallback to defaults
	if clientOpts == nil {
		clientOpts = DefaultOptionsSameHost()
	}

	maxWorkers := clientOpts.MaxConnsPerHost
	pool := &RequestPool{
		client:       NewHTTPClient(clientOpts, errorHandler),
		maxWorkers:   maxWorkers,
		payloadQueue: make(chan payload.PayloadJob, maxWorkers*2),
		results:      make(chan *RawHTTPResponseDetails, maxWorkers*2),
		scanOpts:     scanOpts,
		errorHandler: errorHandler,
		workerPool: &requestWorkerPool{
			ready:  make(chan *requestWorker, maxWorkers),
			stopCh: make(chan struct{}),
		},
	}

	// Initialize worker pool
	pool.workerPool.pool.New = func() interface{} {
		return &requestWorker{
			id:           len(pool.workerPool.workers),
			client:       pool.client,
			jobs:         make(chan payload.PayloadJob, 1),
			results:      make(chan *RawHTTPResponseDetails, 1),
			builder:      NewRequestBuilder(pool.client),
			scanOpts:     scanOpts,
			errorHandler: pool.errorHandler,
			pool:         pool.workerPool,
		}
	}

	// Pre-create workers
	for i := 0; i < maxWorkers; i++ {
		worker := pool.workerPool.pool.Get().(*requestWorker)
		pool.workerPool.workers = append(pool.workerPool.workers, worker)
		pool.workerPool.ready <- worker
	}

	return pool
}

func (p *RequestPool) ActiveWorkers() int {
	active, _ := p.workerPool.getStats()
	return int(active)
}

func (p *requestWorkerPool) activeWorkerCount() int {
	p.lock.Lock()
	defer p.lock.Unlock()
	count := 0
	for _, w := range p.workers {
		if time.Since(w.lastUsed) < 5*time.Second {
			count++
		}
	}
	return count
}

func (p *requestWorkerPool) getStats() (active int32, queued int32) {
	return p.activeWorkers.Load(),
		p.queuedJobs.Load()
}

// RequestBuilder handles request construction
func NewRequestBuilder(client *HttpClient) *RequestBuilder {
	return &RequestBuilder{
		client: client,
	}
}

// Request must contain at least non-zero RequestURI with full url (including
// scheme and host) or non-zero Host header + RequestURI.
//
// Client determines the server to be requested in the following order:
//
//   - from RequestURI if it contains full url with scheme and host;
//   - from Host header otherwise.
//
// The function doesn't follow redirects. Use Get* for following redirects.
// Response is ignored if resp is nil.
//
// ErrNoFreeConns is returned if all DefaultMaxConnsPerHost connections
// to the requested host are busy.
// BuildRequest creates and configures a HTTP request from a bypass job (payload job)
func (rb *RequestBuilder) BuildRequest(req *fasthttp.Request, job payload.PayloadJob) {
	//req.Reset()
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
		rb.client.options.DisableKeepAlive ||
		rb.client.options.ProxyURL != ""

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
		req.Header.Set("Connection", "keep-alive")
		//req.SetConnectionClose()
	}
}

// ProcessRequests handles multiple requests "efficiently"
func (p *RequestPool) ProcessRequests(jobs []payload.PayloadJob) <-chan *RawHTTPResponseDetails {
	results := make(chan *RawHTTPResponseDetails, len(jobs))
	jobsChan := make(chan payload.PayloadJob, p.maxWorkers)

	// Start fixed number of workers
	var wg sync.WaitGroup
	for i := 0; i < p.maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker := p.workerPool.AcquireWorker()
			if worker == nil {
				return
			}
			defer p.workerPool.ReleaseWorker(worker)

			for job := range jobsChan {
				if result := worker.ProcessRequestJob(job); result != nil {
					results <- result
				}
			}
		}()
	}

	// Feed jobs
	go func() {
		for _, job := range jobs {
			jobsChan <- job
		}
		close(jobsChan)
		wg.Wait()
		close(results)
	}()

	return results
}

// To remember!
// ErrNoFreeConns is returned when no free connections available
// to the given host.
//
// Increase the allowed number of connections per host if you
// see this error.
//
// ErrNoFreeConns ErrConnectionClosed may be returned from client methods if the server
// closes connection before returning the first response byte.
//
// If you see this error, then either fix the server by returning
// 'Connection: close' response header before closing the connection
// or add 'Connection: close' request header before sending requests
// to broken server.

func (w *requestWorker) ProcessRequestJob(job payload.PayloadJob) *RawHTTPResponseDetails {
	w.pool.activeWorkers.Add(1)
	defer w.pool.activeWorkers.Add(-1)

	req := w.client.AcquireRequest()
	resp := w.client.AcquireResponse()
	defer w.client.ReleaseRequest(req)
	defer w.client.ReleaseResponse(resp)

	w.builder.BuildRequest(req, job)

	GB403Logger.Debug().DebugToken(job.PayloadToken).Msgf("[%s] Sending request %s\n", job.BypassModule, job.FullURL)

	if err := w.client.DoRaw(req, resp); err != nil {
		err = w.errorHandler.HandleError(err, GB403ErrorHandler.ErrorContext{
			Host:         []byte(job.Host),
			ErrorSource:  []byte("Worker.processJob"),
			BypassModule: []byte(job.BypassModule),
		})
		if err != nil {
			if GB403Logger.IsDebugEnabled() {
				GB403Logger.Error().DebugToken(job.PayloadToken).Msgf("Request failed: %v", err)
			}
			return nil
		}
	}

	return w.ProcessResponseJob(resp, job)
}

// processResponse handles response processing
func (w *requestWorker) ProcessResponseJob(resp *fasthttp.Response, job payload.PayloadJob) *RawHTTPResponseDetails {
	result := &RawHTTPResponseDetails{
		URL:          append([]byte(nil), job.FullURL...),
		BypassModule: append([]byte(nil), job.BypassModule...),
		StatusCode:   resp.StatusCode(),
	}

	// Create a new buffer directly
	headerBuf := &bytesutil.ByteBuffer{}

	// Write status line
	headerBuf.Write(resp.Header.Protocol())
	headerBuf.Write(bytesutil.ToUnsafeBytes(" "))
	headerBuf.B = fasthttp.AppendUint(headerBuf.B, resp.StatusCode())
	headerBuf.Write(bytesutil.ToUnsafeBytes(" "))
	headerBuf.Write(resp.Header.StatusMessage())
	headerBuf.Write(bytesutil.ToUnsafeBytes("\r\n"))

	// Process headers once
	resp.Header.VisitAll(func(key, value []byte) {
		headerBuf.Write(key)
		headerBuf.Write(bytesutil.ToUnsafeBytes(": "))
		headerBuf.Write(value)
		headerBuf.Write(bytesutil.ToUnsafeBytes("\r\n"))
	})
	headerBuf.Write(bytesutil.ToUnsafeBytes("\r\n"))

	// Store headers
	result.ResponseHeaders = append([]byte(nil), headerBuf.B...)

	// Use direct header access methods
	result.ContentType = append([]byte(nil), resp.Header.ContentType()...)
	result.ServerInfo = append([]byte(nil), resp.Header.Server()...)
	if location := resp.Header.PeekBytes(bytes.ToLower([]byte("location"))); len(location) > 0 {
		result.RedirectURL = append([]byte(nil), location...)
	}

	// Process body - get it once
	body := resp.Body()
	result.ContentLength = int64(resp.Header.ContentLength())
	result.ResponseBytes = len(body)

	// Get preview if configured
	if w.scanOpts.ResponseBodyPreviewSize > 0 && len(body) > 0 {
		if len(body) > w.scanOpts.ResponseBodyPreviewSize {
			result.ResponsePreview = append([]byte(nil), body[:w.scanOpts.ResponseBodyPreviewSize]...)
		} else {
			result.ResponsePreview = append([]byte(nil), body...)
		}
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
func (wp *requestWorkerPool) AcquireWorker() *requestWorker {
	select {
	case <-wp.stopCh:
		return nil
	case worker := <-wp.ready:
		worker.lastUsed = time.Now()
		return worker
	case <-time.After(100 * time.Millisecond):
		wp.lock.Lock()
		defer wp.lock.Unlock()

		if len(wp.workers) < cap(wp.ready) {
			worker := wp.pool.Get().(*requestWorker)
			wp.workers = append(wp.workers, worker)
			worker.lastUsed = time.Now()
			return worker
		}
		return nil
	}
}

func (wp *requestWorkerPool) ReleaseWorker(w *requestWorker) {
	w.lastUsed = time.Now()

	wp.lock.Lock()
	defer wp.lock.Unlock()

	if wp.strategy == LIFO {
		wp.workers = append(wp.workers, w)
	} else {
		wp.workers = append([]*requestWorker{w}, wp.workers...)
	}
}

func (wp *requestWorkerPool) startCleanupRoutine() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-wp.stopCh:
				return
			case <-ticker.C:
				wp.cleanIdleWorkers(wp.maxIdleWorkerDuration)
			}
		}
	}()
}

func (wp *requestWorkerPool) cleanIdleWorkers(maxIdleTime time.Duration) {
	threshold := time.Now().Add(-maxIdleTime)
	wp.lock.Lock()
	defer wp.lock.Unlock()

	activeWorkers := make([]*requestWorker, 0, len(wp.workers))
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
	p.closeMu.Do(func() {
		// 1. Signal stop
		close(p.workerPool.stopCh)

		// 2. Wait for workers to finish current jobs
		var wg sync.WaitGroup
		p.workerPool.lock.Lock()
		for _, w := range p.workerPool.workers {
			wg.Add(1)
			go func(worker *requestWorker) {
				defer wg.Done()
				// Give workers time to finish current job
				time.Sleep(100 * time.Millisecond)
			}(w)
		}
		p.workerPool.lock.Unlock()

		// 3. Wait with timeout
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			// Timeout reached
		}

		// 4. Clean up channels
		p.workerPool.lock.Lock()
		for _, w := range p.workerPool.workers {
			safeClose(w.jobs)
			safeClose(w.results)
		}
		p.workerPool.workers = nil
		p.workerPool.lock.Unlock()

		safeClose(p.payloadQueue)
		safeClose(p.results)
	})
}

func safeClose[T any](ch chan T) {
	defer func() {
		// Recover from panic if channel is already closed
		recover()
	}()
	close(ch)
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
func BuildCurlCommandPoc(job payload.PayloadJob) []byte {
	bb := &bytesutil.ByteBuffer{}

	// Use pre-computed curl command
	bb.Write(curlCmd)
	bb.Write(bytesutil.ToUnsafeBytes(" -skgi --path-as-is"))

	// Rest of the function remains the same...
	if job.Method != "GET" {
		bb.Write(bytesutil.ToUnsafeBytes(" -X "))
		bb.Write(bytesutil.ToUnsafeBytes(job.Method))
	}

	// Add headers before URL
	for _, h := range job.Headers {
		bb.Write(bytesutil.ToUnsafeBytes(" -H '"))
		bb.Write(bytesutil.ToUnsafeBytes(h.Header))
		bb.Write(bytesutil.ToUnsafeBytes(": "))
		bb.Write(bytesutil.ToUnsafeBytes(h.Value))
		bb.Write(bytesutil.ToUnsafeBytes("'"))
	}

	// last is URL
	bb.Write(bytesutil.ToUnsafeBytes(" '"))
	bb.Write(bytesutil.ToUnsafeBytes(job.FullURL))
	bb.Write(bytesutil.ToUnsafeBytes("'"))

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

// match HTTP status code in list
func matchStatusCodes(code int, codes []int) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}
