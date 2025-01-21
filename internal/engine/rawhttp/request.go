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

func init() {
	// Initialize curl command
	if runtime.GOOS == "windows" {
		curlCmd = []byte("curl.exe")
	} else {
		curlCmd = []byte("curl")
	}
}

var (
	curlCmd []byte

	// Pool for byte buffers
	curlCmdPool   = &bytesutil.ByteBufferPool{}
	headerBufPool = &bytesutil.ByteBufferPool{}

	// Pre-computed byte slices for static strings
	curlFlags       = []byte(" -skgi --path-as-is")
	curlMethodX     = []byte(" -X ")
	curlHeaderStart = []byte(" -H '")
	strColonSpace   = []byte(": ")
	strSingleQuote  = []byte("'")
	strSpace        = []byte(" ")
	strCRLF         = []byte("\r\n")
	strHTML         = []byte("html")
)

// RequestPool (Top-level manager)
//
//	│
//	├── HttpClient (Handles HTTP connections)
//	│
//	└── RequestWorkerPool (Manages worker instances)
//	       │
//	       └── RequestWorker (Individual workers that process requests)
type RequestPool struct {
	Client       *HttpClient
	WorkerPool   *RequestWorkerPool
	MaxWorkers   int
	PayloadQueue chan payload.PayloadJob
	Results      chan *RawHTTPResponseDetails
	ScanOpts     *ScannerCliOpts
	ErrorHandler *GB403ErrorHandler.ErrorHandler
	CloseMu      sync.Once
}

// ConnPoolStrategyType define strategy of connection pool enqueue/dequeue.
type ConnPoolStrategyType int

const (
	FIFO ConnPoolStrategyType = iota
	LIFO
)

type RequestWorkerPool struct {
	Workers       []*RequestWorker
	Ready         chan *RequestWorker
	Lock          sync.Mutex
	StopCh        chan struct{}
	Pool          sync.Pool
	ActiveWorkers atomic.Int32
	QueuedJobs    atomic.Int32

	// news
	MaxIdleWorkerDuration time.Duration
	LastCleanup           time.Time
	Strategy              ConnPoolStrategyType // FIFO or LIFO
}

// Individual worker that processes requests
type RequestWorker struct {
	Id           int
	Client       *HttpClient
	Jobs         chan payload.PayloadJob
	Results      chan *RawHTTPResponseDetails
	LastUsed     time.Time
	Builder      *RequestBuilder
	ScanOpts     *ScannerCliOpts
	ErrorHandler *GB403ErrorHandler.ErrorHandler
	Pool         *RequestWorkerPool
	RateLimiter  *time.Ticker // per-worker rate limiter
}

type ProgressTracker interface {
	UpdateWorkerStats(moduleName string, totalWorkers int64)
}

// RequestBuilder handles the lifecycle of fasthttp requests
type RequestBuilder struct {
	Client *HttpClient
}

// ScannerCliOpts reference the cli options
type ScannerCliOpts struct {
	MatchStatusCodes        []int
	ResponseBodyPreviewSize int
	ModuleName              string
	MaxWorkers              int
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

func NewRequestPool(clientOpts *HttpClientOptions, scanOpts *ScannerCliOpts, errorHandler *GB403ErrorHandler.ErrorHandler) *RequestPool {
	// Just use the options as provided, with a fallback to defaults
	if clientOpts == nil {
		clientOpts = DefaultHTTPClientOptions()
	}

	maxWorkers := scanOpts.MaxWorkers

	pool := &RequestPool{
		Client:       NewHTTPClient(clientOpts, errorHandler),
		MaxWorkers:   maxWorkers,
		PayloadQueue: make(chan payload.PayloadJob, maxWorkers*2),
		Results:      make(chan *RawHTTPResponseDetails, maxWorkers*2),
		ScanOpts:     scanOpts,
		ErrorHandler: errorHandler,
		WorkerPool: &RequestWorkerPool{
			Ready:  make(chan *RequestWorker, maxWorkers),
			StopCh: make(chan struct{}),
		},
	}

	// Initialize worker pool
	pool.WorkerPool.Pool.New = func() interface{} {
		worker := &RequestWorker{
			Id:           len(pool.WorkerPool.Workers),
			Client:       pool.Client,
			Jobs:         make(chan payload.PayloadJob, 1),
			Results:      make(chan *RawHTTPResponseDetails, 1),
			Builder:      NewRequestBuilder(pool.Client),
			ScanOpts:     scanOpts,
			ErrorHandler: pool.ErrorHandler,
			Pool:         pool.WorkerPool,
		}

		// Create per-worker rate limiter
		if clientOpts.RequestDelay > 0 {
			worker.RateLimiter = time.NewTicker(clientOpts.RequestDelay)
		}

		return worker
	}

	// Pre-create workers
	for i := 0; i < maxWorkers; i++ {
		worker := pool.WorkerPool.Pool.Get().(*RequestWorker)
		pool.WorkerPool.Workers = append(pool.WorkerPool.Workers, worker)
		pool.WorkerPool.Ready <- worker
	}

	return pool
}

func (p *RequestPool) ActiveWorkers() int {
	active, _ := p.WorkerPool.getStats()
	return int(active)
}

func (p *RequestWorkerPool) getStats() (active int32, queued int32) {
	return p.ActiveWorkers.Load(),
		p.QueuedJobs.Load()
}

// RequestBuilder handles request construction
func NewRequestBuilder(client *HttpClient) *RequestBuilder {
	return &RequestBuilder{
		Client: client,
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
}

// ProcessRequests handles multiple requests "efficiently"
func (p *RequestPool) ProcessRequests(jobs []payload.PayloadJob) <-chan *RawHTTPResponseDetails {
	results := make(chan *RawHTTPResponseDetails, len(jobs))
	jobsChan := make(chan payload.PayloadJob, p.MaxWorkers)

	var wg sync.WaitGroup
	for i := 0; i < p.MaxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker := p.WorkerPool.AcquireWorker()
			if worker == nil {
				return
			}
			defer p.WorkerPool.ReleaseWorker(worker)

			for job := range jobsChan {
				// Use worker's rate limiter instead of pool's
				if worker.RateLimiter != nil {
					<-worker.RateLimiter.C
				}
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

func (w *RequestWorker) ProcessRequestJob(job payload.PayloadJob) *RawHTTPResponseDetails {
	w.Pool.ActiveWorkers.Add(1)
	defer w.Pool.ActiveWorkers.Add(-1)

	req := w.Client.AcquireRequest()
	resp := w.Client.AcquireResponse()
	defer w.Client.ReleaseRequest(req)
	defer w.Client.ReleaseResponse(resp)

	w.Builder.BuildRequest(req, job)

	GB403Logger.Debug().DebugToken(job.PayloadToken).Msgf("[%s] Sending request %s\n", job.BypassModule, job.FullURL)

	if err := w.Client.DoRequest(req, resp); err != nil {
		err = w.ErrorHandler.HandleError(err, GB403ErrorHandler.ErrorContext{
			Host:         []byte(job.Host),
			ErrorSource:  []byte("Worker.ProcessRequestJob"),
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
func (w *RequestWorker) ProcessResponseJob(resp *fasthttp.Response, job payload.PayloadJob) *RawHTTPResponseDetails {
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

	// Handle body preview
	if w.ScanOpts.ResponseBodyPreviewSize > 0 && len(body) > 0 {
		previewSize := w.ScanOpts.ResponseBodyPreviewSize
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

// WorkerPool methods
func (wp *RequestWorkerPool) AcquireWorker() *RequestWorker {
	select {
	case <-wp.StopCh:
		return nil
	case worker := <-wp.Ready:
		worker.LastUsed = time.Now()
		return worker
	case <-time.After(100 * time.Millisecond):
		wp.Lock.Lock()
		defer wp.Lock.Unlock()

		if len(wp.Workers) < cap(wp.Ready) {
			worker := wp.Pool.Get().(*RequestWorker)
			wp.Workers = append(wp.Workers, worker)
			worker.LastUsed = time.Now()
			return worker
		}
		return nil
	}
}

func (wp *RequestWorkerPool) ReleaseWorker(w *RequestWorker) {
	w.LastUsed = time.Now()

	wp.Lock.Lock()
	defer wp.Lock.Unlock()

	if wp.Strategy == LIFO {
		wp.Workers = append(wp.Workers, w)
	} else {
		wp.Workers = append([]*RequestWorker{w}, wp.Workers...)
	}
}

func (p *RequestPool) Close() {
	p.CloseMu.Do(func() {
		// First signal stop
		close(p.WorkerPool.StopCh)

		// Clean up workers
		p.WorkerPool.Lock.Lock()
		for _, w := range p.WorkerPool.Workers {
			if w.RateLimiter != nil {
				w.RateLimiter.Stop()
			}
		}
		p.WorkerPool.Lock.Unlock()

		// Clean up channels last
		safeClose(p.PayloadQueue)
		safeClose(p.Results)
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
	// Get buffer from pool
	bb := curlCmdPool.Get()
	defer curlCmdPool.Put(bb)
	bb.Reset()

	// Build command
	bb.Write(curlCmd)
	bb.Write(curlFlags)

	if job.Method != "GET" {
		bb.Write(curlMethodX)
		bb.Write(bytesutil.ToUnsafeBytes(job.Method))
	}

	// Headers
	for _, h := range job.Headers {
		bb.Write(curlHeaderStart)
		bb.Write(bytesutil.ToUnsafeBytes(h.Header))
		bb.Write(strColonSpace)
		bb.Write(bytesutil.ToUnsafeBytes(h.Value))
		bb.Write(strSingleQuote)
	}

	// URL
	bb.Write(strSpace)
	bb.Write(strSingleQuote)
	bb.Write(bytesutil.ToUnsafeBytes(job.FullURL))
	bb.Write(strSingleQuote)

	// Return a copy of the buffer's contents
	return append([]byte(nil), bb.B...)
}

// Helper function to peek a header key case insensitive
func PeekHeaderKeyCaseInsensitive(h *fasthttp.ResponseHeader, key []byte) []byte {
	// Try original
	if v := h.PeekBytes(key); len(v) > 0 {
		return v
	}

	// Otherwise lowercase it
	lowerKey := bytes.ToLower(key)
	return h.PeekBytes(lowerKey)
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
