package rawhttp

import (
	"sync/atomic"
	"time"

	"github.com/alitto/pond/v2"
	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	"github.com/valyala/fasthttp"
)

// RequestWorkerPool manages concurrent HTTP request/response processing
type RequestWorkerPool struct {
	httpClient   *HTTPClient
	errorHandler *GB403ErrorHandler.ErrorHandler
	pool         pond.Pool
	throttler    *Throttler

	// Request rate tracking
	requestStartTime atomic.Int64  // For elapsed time calculation
	peakRequestRate  atomic.Uint64 // For tracking peak rate
}

// NewWorkerPool initializes a new RequestWorkerPool instance
func NewRequestWorkerPool(opts *HTTPClientOptions, maxWorkers int, errorHandler *GB403ErrorHandler.ErrorHandler) *RequestWorkerPool {
	wp := &RequestWorkerPool{
		httpClient:   NewHTTPClient(opts, errorHandler),
		errorHandler: errorHandler,
		pool:         pond.NewPool(maxWorkers),
		throttler:    NewThrottler(nil),
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
	group := wp.pool.NewGroup()

	for _, job := range jobs {
		job := job // Capture for closure
		group.Submit(func() {
			if resp := wp.ProcessRequestResponseJob(job); resp != nil {
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
	wp.ResetPeakRate()
	wp.throttler.Reset()
	wp.httpClient.Close()
}

// ProcessRequestResponseJob handles a single job: builds request, sends it, and processes response
func (wp *RequestWorkerPool) ProcessRequestResponseJob(job payload.PayloadJob) *RawHTTPResponseDetails {
	req := wp.httpClient.AcquireRequest()
	resp := wp.httpClient.AcquireResponse()
	defer wp.httpClient.ReleaseRequest(req)
	defer wp.httpClient.ReleaseResponse(resp)

	// Apply current delay if throttling is active
	if wp.throttler != nil {
		if delay := wp.throttler.GetDelay(); delay > 0 {
			time.Sleep(delay)
		}
	}

	// Build HTTP Request
	if err := wp.BuildRequestTask(req, job); err != nil {
		if err := wp.errorHandler.HandleError(err, GB403ErrorHandler.ErrorContext{
			ErrorSource:  []byte("RequestWorkerPool.BuildRequestTask"),
			Host:         []byte(job.Host),
			BypassModule: []byte(job.BypassModule),
		}); err != nil {
			return nil
		}
	}

	respTime, err := wp.SendRequestTask(req, resp)
	if err != nil {
		// Handle the error and get result
		handledErr := wp.errorHandler.HandleError(err, GB403ErrorHandler.ErrorContext{
			ErrorSource:  []byte("RequestWorkerPool.SendRequestTask"),
			Host:         []byte(job.Host),
			BypassModule: []byte(job.BypassModule),
		})

		if handledErr != nil {
			// Non-whitelisted error occurred, stop processing
			return nil
		}
		// Whitelisted error, continue processing
	}

	// Process response
	result := wp.ProcessResponseTask(resp, job)
	if result != nil {
		result.ResponseTime = respTime
	}

	// Handle throttling based on response
	if wp.throttler != nil {
		if wp.throttler.ShouldThrottleOnStatusCode(result.StatusCode) {
			wp.throttler.GetDelay() // This will update the delay based on attempts
			//GB403Logger.Warning().Msgf("Throttling request due to status code: %d", result.StatusCode)
		}
	}

	return result
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
func (wp *RequestWorkerPool) SendRequestTask(req *fasthttp.Request, resp *fasthttp.Response) (int64, error) {
	return wp.httpClient.DoRequest(req, resp)
}

// processResponse processes the HTTP response and extracts details
func (wp *RequestWorkerPool) ProcessResponseTask(resp *fasthttp.Response, job payload.PayloadJob) *RawHTTPResponseDetails {
	return ProcessHTTPResponse(wp.httpClient, resp, job)
}
