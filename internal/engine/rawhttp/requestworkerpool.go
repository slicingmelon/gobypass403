package rawhttp

import (
	"crypto/rand"
	"math"
	"math/big"
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
	httpClient   *HTTPClient
	errorHandler *GB403ErrorHandler.ErrorHandler
	pool         pond.Pool
	throttler    *Throttler

	// Request rate tracking
	requestStartTime atomic.Int64  // For elapsed time calculation
	peakRequestRate  atomic.Uint64 // For tracking peak rate
}

type ThrottleConfig struct {
	BaseRequestDelay        time.Duration
	MaxRequestDelay         time.Duration
	ExponentialRequestDelay float64 // Exponential request delay
	RequestDelayJitter      int     // For random delay, percentage of variation (0-100)
	ThrottleOnStatusCodes   []int   // Status codes that trigger throttling
}

// Throttler handles request rate limiting
type Throttler struct {
	config       atomic.Pointer[ThrottleConfig]
	attempts     atomic.Int32 // Counts consecutive throttled responses
	lastDelay    atomic.Int64 // Last calculated delay in nanoseconds
	isThrottling atomic.Bool  // Indicates if auto throttling is currently active
}

// DefaultThrottleConfig returns sensible defaults
func DefaultThrottleConfig() *ThrottleConfig {
	return &ThrottleConfig{
		BaseRequestDelay:        100 * time.Millisecond,
		MaxRequestDelay:         5000 * time.Millisecond,
		RequestDelayJitter:      20,  // 20% of the base request delay
		ExponentialRequestDelay: 2.0, // Each throttle doubles the delay
		ThrottleOnStatusCodes:   []int{429, 503, 507},
	}
}

// NewThrottler creates a new throttler instance
func NewThrottler(config *ThrottleConfig) *Throttler {
	t := &Throttler{}
	if config == nil {
		config = DefaultThrottleConfig()
	}
	t.config.Store(config)
	return t
}

// ShouldThrottle checks if we should throttle based on status code
func (t *Throttler) ShouldThrottle(statusCode int) bool {
	config := t.config.Load()
	if matchStatusCodes(statusCode, config.ThrottleOnStatusCodes) {
		wasThrottling := t.isThrottling.Swap(true)
		t.attempts.Add(1)
		if !wasThrottling {
			GB403Logger.Warning().Msgf("Auto throttling enabled due to status code: %d", statusCode)
		}
		return true
	}
	return false
}

// GetDelay calculates the next delay based on config and attempts
func (t *Throttler) GetDelay() time.Duration {
	config := t.config.Load()
	delay := config.BaseRequestDelay

	// Apply exponential delay if configured
	if config.ExponentialRequestDelay > 0 {
		attempts := t.attempts.Load()
		multiplier := math.Pow(config.ExponentialRequestDelay, float64(attempts))
		delay = time.Duration(float64(config.BaseRequestDelay) * multiplier)
	}

	// Apply jitter if configured
	if config.RequestDelayJitter > 0 {
		jitterRange := int64(float64(delay.Nanoseconds()) * float64(config.RequestDelayJitter) / 100.0)
		if jitter, err := rand.Int(rand.Reader, big.NewInt(jitterRange)); err == nil {
			delay += time.Duration(jitter.Int64())
		}
	}

	// Ensure we don't exceed max delay
	if delay > config.MaxRequestDelay {
		delay = config.MaxRequestDelay
	}

	t.lastDelay.Store(int64(delay))
	return delay
}

// UpdateThrottleConfig safely updates throttle configuration
func (t *Throttler) UpdateThrottleConfig(config *ThrottleConfig) {
	t.config.Store(config)
	t.attempts.Store(0) // Reset attempts counter
}

// Reset resets the throttler state
func (t *Throttler) Reset() {
	wasThrottling := t.isThrottling.Swap(false)
	t.attempts.Store(0)
	t.lastDelay.Store(0)
	if wasThrottling {
		GB403Logger.Info().Msgf("Auto throttling disabled - returning to normal request rate")
	}
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

// GetRequestRate returns the current requests per second
func (wp *RequestWorkerPool) GetRequestRate() uint64 {
	currentTime := time.Now().UnixNano()
	elapsedSeconds := float64(currentTime-wp.requestStartTime.Load()) / float64(time.Second)

	if elapsedSeconds < 0.1 { // Minimum 100ms elapsed
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

// GetAverageRequestRate returns the same as GetRequestRate
// since we're already calculating based on total progress
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
	wp.ResetPeakRate()
	wp.pool.StopAndWait()
	wp.httpClient.Close()
}

// ProcessRequestResponseJob handles a single job: builds request, sends it, and processes response
func (wp *RequestWorkerPool) ProcessRequestResponseJob(job payload.PayloadJob) *RawHTTPResponseDetails {
	startTime := time.Now()

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

	// Send request using SendRequestTask
	if err := wp.SendRequestTask(req, resp); err != nil {
		if err := wp.errorHandler.HandleError(err, GB403ErrorHandler.ErrorContext{
			ErrorSource:  []byte("RequestWorkerPool.SendRequestTask"),
			Host:         []byte(job.Host),
			BypassModule: []byte(job.BypassModule),
		}); err != nil {
			return nil
		}
	}

	// Process response
	result := wp.ProcessResponseTask(resp, job)
	if result != nil {
		result.ResponseTime = time.Since(startTime).Milliseconds()
	}

	// Handle throttling based on response
	if wp.throttler != nil {
		if wp.throttler.ShouldThrottle(result.StatusCode) {
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
func (wp *RequestWorkerPool) SendRequestTask(req *fasthttp.Request, resp *fasthttp.Response) error {
	return wp.httpClient.DoRequest(req, resp)
}

// processResponse processes the HTTP response and extracts details
func (wp *RequestWorkerPool) ProcessResponseTask(resp *fasthttp.Response, job payload.PayloadJob) *RawHTTPResponseDetails {
	return ProcessHTTPResponse(wp.httpClient, resp, job)
}
