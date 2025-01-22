package rawhttp

import (
	"fmt"

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

// RequestWorkerPool manages concurrent HTTP request processing using pond
type RequestWorkerPool struct {
	httpClient   *HttpClient
	errorHandler *GB403ErrorHandler.ErrorHandler
	pool         pond.Pool
}

// GetPoolStats returns current pool statistics
func (wp *RequestWorkerPool) GetCurrentStats() (running int64, waiting uint64) {
	return wp.pool.RunningWorkers(), wp.pool.WaitingTasks()
}

// NewWorkerPool initializes a new RequestWorkerPool instance
func NewWorkerPool(opts *HttpClientOptions, maxWorkers int, errorHandler *GB403ErrorHandler.ErrorHandler) *RequestWorkerPool {
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
}

// processJob handles a single job: builds request, sends it, and processes response
func (wp *RequestWorkerPool) processJob(job payload.PayloadJob) *RawHTTPResponseDetails {
	req := wp.httpClient.AcquireRequest()
	resp := wp.httpClient.AcquireResponse()
	defer wp.httpClient.ReleaseRequest(req)
	defer wp.httpClient.ReleaseResponse(resp)

	fmt.Printf("Processing request for URL: %s\n", job.FullURL)

	// Build request
	if err := wp.BuildRequestTask(req, job); err != nil {
		if err := wp.errorHandler.HandleError(err, GB403ErrorHandler.ErrorContext{
			ErrorSource:  []byte("RequestWorkerPool.BuildRequest"),
			Host:         []byte(job.Host),
			BypassModule: []byte(job.BypassModule),
		}); err != nil {
			return nil
		}
	}

	// Send request
	if err := wp.httpClient.DoRequest(req, resp); err != nil {
		//fmt.Printf("Error sending request: %v\n", err)
		if err := wp.errorHandler.HandleError(err, GB403ErrorHandler.ErrorContext{
			ErrorSource:  []byte("RequestWorkerPool.SendRequest"),
			Host:         []byte(job.Host),
			BypassModule: []byte(job.BypassModule),
		}); err != nil {
			return nil
		}
	}

	// Continue processing response even if we got a whitelisted error
	return wp.ProcessResponseTask(resp, job)
}

// buildRequest constructs the HTTP request
func (wp *RequestWorkerPool) BuildRequestTask(req *fasthttp.Request, job payload.PayloadJob) error {
	return BuildHTTPRequest(wp.httpClient, req, job)
}

// SendRequest sends the HTTP request
func (wp *RequestWorkerPool) SendRequestTask(req *fasthttp.Request, resp *fasthttp.Response) error {
	return wp.httpClient.DoRequest(req, resp)
}

// processResponse processes the HTTP response and extracts details
func (wp *RequestWorkerPool) ProcessResponseTask(resp *fasthttp.Response, job payload.PayloadJob) *RawHTTPResponseDetails {
	statusCode := resp.StatusCode()
	body := resp.Body()

	if len(body) > wp.httpClient.GetHTTPClientOptions().MaxResponseBodySize {
		body = body[:wp.httpClient.GetHTTPClientOptions().MaxResponseBodySize]
	}

	result := &RawHTTPResponseDetails{
		URL:           []byte(job.FullURL),
		StatusCode:    statusCode,
		ContentLength: int64(resp.Header.ContentLength()),
		ResponseBytes: len(body),
	}

	if wp.httpClient.GetHTTPClientOptions().MaxResponseBodySize > 0 && len(body) > 0 {
		previewSize := wp.httpClient.GetHTTPClientOptions().MaxResponseBodySize
		if len(body) > previewSize {
			result.ResponsePreview = append([]byte(nil), body[:previewSize]...)
		} else {
			result.ResponsePreview = append([]byte(nil), body...)
		}
	}

	return result
}

// func main() {
// 	// Initialize error handler
// 	errorHandler := GB403ErrorHandler.NewErrorHandler(32)
// 	httpclientopts := DefaultHTTPClientOptions()
// 	httpclientopts.ReadBufferSize = 8092      // 8KB
// 	httpclientopts.WriteBufferSize = 8092     // 8KB
// 	httpclientopts.MaxResponseBodySize = 4096 // 8KB
// 	httpclientopts.StreamResponseBody = true

// 	// Create worker pool
// 	pool := NewWorkerPool(httpclientopts, 10, errorHandler)
// 	defer pool.Close()

// 	// Generate test URLs
// 	baseURL := "https://localhost/test/"
// 	var jobs []payload.PayloadJob
// 	for i := 1; i <= 200; i++ {
// 		jobs = append(jobs, payload.PayloadJob{
// 			Host:         "localhost",
// 			Method:       "GET",
// 			FullURL:      fmt.Sprintf("%s%d", baseURL, i),
// 			PayloadToken: strconv.Itoa(i),
// 			Headers: []payload.Header{
// 				{Header: "User-Agent", Value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
// 			},
// 		})
// 	}

// 	// Start processing
// 	fmt.Printf("Starting to process %d URLs with %d workers\n", len(jobs), 10)
// 	startTime := time.Now()

// 	results := pool.ProcessRequests(jobs)

// 	// Process results as they come in
// 	successCount := 0
// 	for result := range results {
// 		if result != nil {
// 			successCount++
// 			fmt.Printf("URL: %s - Status: %d - Content Length: %d bytes - Response Bytes: %d bytes\n",
// 				string(result.URL),
// 				result.StatusCode,
// 				result.ContentLength,
// 				result.ResponseBytes,
// 			)
// 			running, waiting := pool.GetCurrentStats()
// 			fmt.Printf("\rActive Workers: %d | Queued: %d", running, waiting)
// 		}
// 	}

// 	// Print statistics
// 	duration := time.Since(startTime)
// 	// stats := pool.GetPoolStats()

// 	fmt.Printf("\nExecution Summary:\n")
// 	fmt.Printf("Total time: %v\n", duration)
// 	fmt.Printf("Successful requests: %d/%d\n", successCount, len(jobs))
// 	//fmt.Printf("Running workers: %d\n", stats.RunningWorkers)
// 	//fmt.Printf("Completed tasks: %d\n", stats.CompletedTasks)
// 	//fmt.Printf("Failed tasks: %d\n", stats.FailedTasks)
// 	fmt.Printf("Average time per request: %v\n", duration/time.Duration(len(jobs)))

// 	fmt.Println("")
// 	errorHandler.PrintErrorStats()
// }
