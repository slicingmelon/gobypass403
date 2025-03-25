package rawhttp

import (
	"context"
	"errors"
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

	if maxWorkers > opts.MaxConnsPerHost {
		// Add 50% more connections than workers for buffer
		opts.MaxConnsPerHost = maxWorkers + (maxWorkers / 2)
	}

	wp := &RequestWorkerPool{
		httpClient: NewHTTPClient(opts),
		ctx:        ctx,
		cancel:     cancel,
		//pool:       pond.NewPool(maxWorkers, pond.WithContext(ctx), pond.WithQueueSize(500)),
		pool:       pond.NewPool(maxWorkers),
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
// func (wp *RequestWorkerPool) ProcessRequests(bypassPayloads []payload.BypassPayload) <-chan *RawHTTPResponseDetails {
// 	results := make(chan *RawHTTPResponseDetails)
// 	group := wp.pool.NewGroupContext(wp.ctx)

// 	for _, bypassPayload := range bypassPayloads {
// 		bypassPayload := bypassPayload // Capture for closure
// 		group.SubmitErr(func() error {
// 			// First check if context is already done to avoid unnecessary work
// 			select {
// 			case <-wp.ctx.Done():
// 				return nil
// 			default:
// 			}

// 			resp, err := wp.ProcessRequestResponseJob(bypassPayload)

// 			// If we hit the critical error, return it to stop the group
// 			if err == ErrReqFailedMaxConsecutiveFails {
// 				GB403Logger.Warning().Msgf("[ErrReqFailedMaxConsecutiveFails] Worker pool cancelled: max consecutive failures reached for module [%s]\n",
// 					wp.httpClient.options.BypassModule)
// 				return err // This will cause group.Wait() to return this error
// 			}

// 			// Only send valid responses to the results channel
// 			if resp != nil {
// 				select {
// 				case <-wp.ctx.Done():
// 					return nil
// 				case results <- resp:
// 				}
// 			}

// 			return nil
// 		})
// 	}

// 	// Process the group in a separate goroutine
// 	go func() {
// 		defer close(results)

// 		// Wait for all tasks or first critical error
// 		err := group.Wait()

// 		if errors.Is(err, ErrReqFailedMaxConsecutiveFails) {
// 			// Critical error occurred, cancel context and log
// 			GB403Logger.Warning().Msgf("Worker pool cancelled: max consecutive failures reached for module [%s]\n",
// 				wp.httpClient.options.BypassModule)
// 			wp.cancel() // Cancel context to stop any pending operations
// 			wp.pool.Stop()
// 		}
// 	}()

// 	return results
// }

func (wp *RequestWorkerPool) ProcessRequests(bypassPayloads []payload.BypassPayload) <-chan *RawHTTPResponseDetails {
	results := make(chan *RawHTTPResponseDetails) // Buffered channel
	var cancelled atomic.Bool

	// Create task group with context for cancellation
	group := wp.pool.NewGroupContext(wp.ctx)

	for _, bypassPayload := range bypassPayloads {
		bypassPayload := bypassPayload // Capture for closure
		group.SubmitErr(func() error {
			// Fast check before any work
			if cancelled.Load() {
				return nil
			}

			// Standard context check
			select {
			case <-wp.ctx.Done():
				return nil
			default:
			}

			resp, err := wp.ProcessRequestResponseJob(bypassPayload)

			// Critical error - stop everything
			if err == ErrReqFailedMaxConsecutiveFails {
				if !cancelled.Swap(true) {
					// Only log and cancel once
					GB403Logger.Warning().Msgf("Worker pool cancelled: max consecutive failures reached for module [%s]\n",
						wp.httpClient.options.BypassModule)

					// Cancel context
					wp.cancel()
				}
				return err
			}

			// Only send valid responses
			if resp != nil && !cancelled.Load() {
				select {
				case <-wp.ctx.Done():
					return nil
				case results <- resp:
				}
			}

			return nil
		})
	}

	// Handle completion or error
	go func() {
		defer close(results)

		err := group.Wait()

		if err != nil {
			if errors.Is(err, ErrReqFailedMaxConsecutiveFails) && !cancelled.Load() {
				GB403Logger.Warning().Msgf("[!!!] Worker pool Wait() returned max consecutive failures for [%s]\n\n",
					wp.httpClient.GetHTTPClientOptions().BypassModule)
				//wp.cancel()
				//group.Stop()
				//wp.pool.Stop()
			} else if err != context.Canceled && !cancelled.Load() {
				GB403Logger.Warning().Msgf("Worker pool for [%s] returned unexpected error: %v\n\n",
					wp.httpClient.GetHTTPClientOptions().BypassModule, err)
			}
		}

		GB403Logger.Debug().Msgf("Worker pool for module [%s] completed",
			wp.httpClient.GetHTTPClientOptions().BypassModule)
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
func (wp *RequestWorkerPool) ProcessRequestResponseJob(bypassPayload payload.BypassPayload) (*RawHTTPResponseDetails, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()

	// Ensure both request and response are released
	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()

	if err := BuildRawHTTPRequest(wp.httpClient, req, bypassPayload); err != nil {
		return nil, err
	}

	respTime, err := wp.httpClient.DoRequest(req, resp, bypassPayload)
	if err != nil {
		// Pass through the critical error for handling at higher level
		if err == ErrReqFailedMaxConsecutiveFails {
			return nil, ErrReqFailedMaxConsecutiveFails
		}
		return nil, err
	}

	// Process response and get result
	result := ProcessHTTPResponse(wp.httpClient, resp, bypassPayload)
	if result != nil {
		result.ResponseTime = respTime
	}

	return result, nil
}

// buildRequest constructs the raw HTTP request
func (wp *RequestWorkerPool) BuildRawRequestTask(req *fasthttp.Request, bypassPayload payload.BypassPayload) error {
	if err := BuildRawHTTPRequest(wp.httpClient, req, bypassPayload); err != nil {
		return GB403ErrorHandler.GetErrorHandler().HandleErrorAndContinue(err, GB403ErrorHandler.ErrorContext{
			ErrorSource:  "BuildRawRequestTask",
			Host:         payload.BypassPayloadToBaseURL(bypassPayload),
			BypassModule: bypassPayload.BypassModule,
			DebugToken:   bypassPayload.PayloadToken,
		})
	}
	return nil
}

// SendRequest sends the HTTP request
func (wp *RequestWorkerPool) SendRequestTask(req *fasthttp.Request, resp *fasthttp.Response, bypassPayload payload.BypassPayload) (int64, error) {
	return wp.httpClient.DoRequest(req, resp, bypassPayload)
}

// processResponse processes the HTTP response and extracts details
func (wp *RequestWorkerPool) ProcessResponseTask(resp *fasthttp.Response, bypassPayload payload.BypassPayload) *RawHTTPResponseDetails {
	return ProcessHTTPResponse(wp.httpClient, resp, bypassPayload)
}
