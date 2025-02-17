package rawhttp

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/alitto/pond/v2"
	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/valyala/fasthttp"
)

// RequestWorkerPool manages concurrent HTTP request/response processing
type RequestWorkerPool struct {
	httpClient *HTTPClient
	ctx        context.Context
	cancel     context.CancelFunc
	pool       pond.Pool
	// Request rate tracking
	requestStartTime atomic.Int64  // For elapsed time calculation
	peakRequestRate  atomic.Uint64 // For tracking peak rate
	maxWorkers       int
}

// NewWorkerPool initializes a new RequestWorkerPool instance
func NewRequestWorkerPool(opts *HTTPClientOptions, maxWorkers int) *RequestWorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	wp := &RequestWorkerPool{
		httpClient: NewHTTPClient(opts),
		ctx:        ctx,
		cancel:     cancel,
		pool:       pond.NewPool(maxWorkers, pond.WithContext(ctx)),
		maxWorkers: maxWorkers,
	}

	// Initialize start time
	wp.requestStartTime.Store(time.Now().UnixNano())
	wp.ResetPeakRate()
	return wp
}

// RequestWorkerPoolStats utilities -> get current pool statistics
// Each worker pool instance exposes useful metrics that can be queried through the following methods:
// pool.RunningWorkers() int64: Current number of running workers
// pool.SubmittedTasks() uint64: Total number of tasks submitted since the pool was created
// pool.WaitingTasks() uint64: Current number of tasks in the queue that are waiting to be executed
// pool.SuccessfulTasks() uint64: Total number of tasks that have successfully completed their execution since the pool was created
// pool.FailedTasks() uint64: Total number of tasks that completed with panic since the pool was created
// pool.CompletedTasks() uint64: Total number of tasks that have completed their execution either successfully or with panic since the pool was created
func (wp *RequestWorkerPool) GetReqWPActiveWorkers() (running int64) {
	return wp.pool.RunningWorkers()
}

func (wp *RequestWorkerPool) GetReqWPSubmittedTasks() (submitted uint64) {
	return wp.pool.SubmittedTasks()
}

func (wp *RequestWorkerPool) GetReqWPWaitingTasks() (waiting uint64) {
	return wp.pool.WaitingTasks()
}

func (wp *RequestWorkerPool) GetReqWPCompletedTasks() (completed uint64) {
	return wp.pool.CompletedTasks()
}

// GetRequestRate returns the current requests per second
func (wp *RequestWorkerPool) GetRequestRate() uint64 {
	currentTime := time.Now().UnixNano()
	elapsedSeconds := float64(currentTime-wp.requestStartTime.Load()) / float64(time.Second)

	if elapsedSeconds < 0.1 {
		return 0
	}

	// Use SubmittedTasks for real-time rate
	submittedTasks := wp.GetReqWPSubmittedTasks()

	// Calculate rate based on submitted tasks and elapsed time
	rate := uint64(float64(submittedTasks) / elapsedSeconds)

	// Update peak rate if current rate is higher
	currentPeak := wp.peakRequestRate.Load()
	if rate > currentPeak {
		wp.peakRequestRate.Store(rate)
	}

	return rate
}

// GetAverageRequestRate returns the live request rate
func (wp *RequestWorkerPool) GetAverageRequestRate() uint64 {
	currentTime := time.Now().UnixNano()
	elapsedSeconds := float64(currentTime-wp.requestStartTime.Load()) / float64(time.Second)

	if elapsedSeconds < 0.1 {
		return 0
	}

	// Use CompletedTasks for average throughput (actual processed requests)
	completedTasks := wp.GetReqWPCompletedTasks()

	return uint64(float64(completedTasks) / elapsedSeconds)
}

// GetPeakRequestRate returns the highest observed submission rate
func (wp *RequestWorkerPool) GetPeakRequestRate() uint64 {
	return wp.peakRequestRate.Load()
}

// ResetPeakRate resets the peak rate counter
func (wp *RequestWorkerPool) ResetPeakRate() {
	wp.peakRequestRate.Store(0)
}

// ProcessRequests handles multiple payload jobs
func (wp *RequestWorkerPool) ProcessRequests(jobs []payload.PayloadJob) <-chan *RawHTTPResponseDetails {
	results := make(chan *RawHTTPResponseDetails)
	group := wp.pool.NewGroupContext(wp.ctx)

	for _, job := range jobs {
		job := job // Capture for closure
		group.Submit(func() {
			if resp := wp.ProcessRequestResponseJob(job); resp != nil {
				select {
				case <-wp.ctx.Done():
					return
				case results <- resp:
				}
			}
		})
	}

	go func() {
		defer close(results)
		select {
		case <-wp.ctx.Done():
			// Context was cancelled (due to max consecutive failures)
			GB403Logger.Warning().Msgf("Worker pool cancelled: max consecutive failures reached for module [%s]\n", wp.httpClient.options.BypassModule)
			wp.pool.StopAndWait() // Ensure all workers are stopped
			return
		case <-group.Done():
			// Normal completion
		}
	}()

	return results
}

func (wp *RequestWorkerPool) Close() {
	wp.cancel()           // Cancel context if not already done
	wp.pool.StopAndWait() // Ensure all workers are stopped
	wp.ResetPeakRate()
	wp.httpClient.Close()
}

// ProcessRequestResponseJob handles a single job: builds request, sends it, and processes response
func (wp *RequestWorkerPool) ProcessRequestResponseJob(job payload.PayloadJob) *RawHTTPResponseDetails {
	req := wp.httpClient.AcquireRequest()
	resp := wp.httpClient.AcquireResponse()
	defer wp.httpClient.ReleaseRequest(req)
	defer wp.httpClient.ReleaseResponse(resp)

	if err := BuildRawHTTPRequest(wp.httpClient, req, job); err != nil {
		handleErr := GB403ErrorHandler.GetErrorHandler().HandleError(err, GB403ErrorHandler.ErrorContext{
			ErrorSource:  []byte("RequestWorkerPool.BuildRawRequestTask"),
			Host:         []byte(job.Host),
			BypassModule: []byte(job.BypassModule),
		})
		if handleErr != nil {
			return nil
		}
	}

	// DoRequest already handles error logging/handling
	respTime, err := wp.httpClient.DoRequest(req, resp, job)
	if err != nil {
		if err == ErrReqFailedMaxConsecutiveFails {
			GB403Logger.Warning().Msgf("Cancelling current bypass module due to max consecutive failures reached for module [%s]\n", wp.httpClient.options.BypassModule)
			wp.Close()
			return nil
		}
	}

	// Let ProcessHTTPResponse handle its own resource lifecycle
	result := ProcessHTTPResponse(wp.httpClient, resp, job)
	if result != nil {
		result.ResponseTime = respTime
	}

	return result
}

// buildRequest constructs the HTTP request
func (wp *RequestWorkerPool) BuildRawRequestTask(req *fasthttp.Request, job payload.PayloadJob) error {
	return BuildRawHTTPRequest(wp.httpClient, req, job)
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
func (wp *RequestWorkerPool) SendRequestTask(req *fasthttp.Request, resp *fasthttp.Response, job payload.PayloadJob) (int64, error) {
	return wp.httpClient.DoRequest(req, resp, job)
}

// processResponse processes the HTTP response and extracts details
func (wp *RequestWorkerPool) ProcessResponseTask(resp *fasthttp.Response, job payload.PayloadJob) *RawHTTPResponseDetails {
	return ProcessHTTPResponse(wp.httpClient, resp, job)
}
