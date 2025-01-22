package rawhttp

import (
	"github.com/alitto/pond/v2"
	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	"github.com/valyala/fasthttp"
)

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

// RequestWorkerPool manages concurrent HTTP request/response processing
type RequestWorkerPool struct {
	httpClient   *HttpClient
	errorHandler *GB403ErrorHandler.ErrorHandler
	pool         pond.Pool
}

// GetPoolStats returns current pool statistics
// Each worker pool instance exposes useful metrics that can be queried through the following methods:
// pool.RunningWorkers() int64: Current number of running workers
// pool.SubmittedTasks() uint64: Total number of tasks submitted since the pool was created
// pool.WaitingTasks() uint64: Current number of tasks in the queue that are waiting to be executed
// pool.SuccessfulTasks() uint64: Total number of tasks that have successfully completed their execution since the pool was created
// pool.FailedTasks() uint64: Total number of tasks that completed with panic since the pool was created
// pool.CompletedTasks() uint64: Total number of tasks that have completed their execution either successfully or with panic since the pool was created
func (wp *RequestWorkerPool) GetCurrentStats() (running int64, waiting uint64) {
	return wp.pool.RunningWorkers(), wp.pool.WaitingTasks()
}

// NewWorkerPool initializes a new RequestWorkerPool instance
func NewRequestWorkerPool(opts *HttpClientOptions, maxWorkers int, errorHandler *GB403ErrorHandler.ErrorHandler) *RequestWorkerPool {
	return &RequestWorkerPool{
		httpClient:   NewHTTPClient(opts, errorHandler),
		errorHandler: errorHandler,
		pool:         pond.NewPool(maxWorkers),
	}
}

// ProcessRequests handles multiple payload jobs
func (wp *RequestWorkerPool) ProcessRequests(jobs []payload.PayloadJob) <-chan *RawHTTPResponseDetails {
	results := make(chan *RawHTTPResponseDetails)
	group := wp.pool.NewGroup()

	for _, job := range jobs {
		job := job // Capture for closure
		group.Submit(func() {
			if resp := wp.processJob(job); resp != nil {
				results <- resp
			}
		})
	}

	// Close results channel when all tasks complete
	go func() {
		group.Wait()
		close(results)
	}()

	return results
}

// Close gracefully shuts down the worker pool
func (wp *RequestWorkerPool) Close() {
	wp.pool.StopAndWait()
	wp.httpClient.Close()
}

// processJob handles a single job: builds request, sends it, and processes response
func (wp *RequestWorkerPool) processJob(job payload.PayloadJob) *RawHTTPResponseDetails {
	req := wp.httpClient.AcquireRequest()
	resp := wp.httpClient.AcquireResponse()
	defer wp.httpClient.ReleaseRequest(req)
	defer wp.httpClient.ReleaseResponse(resp)

	// Build HTTP Request
	if err := wp.BuildRequestTask(req, job); err != nil {
		if err := wp.errorHandler.HandleError(err, GB403ErrorHandler.ErrorContext{
			ErrorSource:  []byte("RequestWorkerPool.BuildRequest"),
			Host:         []byte(job.Host),
			BypassModule: []byte(job.BypassModule),
		}); err != nil {
			return nil
		}
	}

	// Send request using SendRequestTask
	if err := wp.SendRequestTask(req, resp); err != nil {
		if err := wp.errorHandler.HandleError(err, GB403ErrorHandler.ErrorContext{
			ErrorSource:  []byte("RequestWorkerPool.SendRequest"),
			Host:         []byte(job.Host),
			BypassModule: []byte(job.BypassModule),
		}); err != nil {
			return nil
		}
	}

	return wp.ProcessResponseTask(resp, job)
}

// buildRequest constructs the HTTP request
func (wp *RequestWorkerPool) BuildRequestTask(req *fasthttp.Request, job payload.PayloadJob) error {
	return BuildHTTPRequest(wp.httpClient, req, job)
}

// SendRequest sends the HTTP request
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
func (wp *RequestWorkerPool) SendRequestTask(req *fasthttp.Request, resp *fasthttp.Response) error {
	return wp.httpClient.DoRequest(req, resp)
}

// processResponse processes the HTTP response and extracts details
func (wp *RequestWorkerPool) ProcessResponseTask(resp *fasthttp.Response, job payload.PayloadJob) *RawHTTPResponseDetails {
	return ProcessHTTPResponse(wp.httpClient, resp, job)
}
