package scanner

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fortio.org/progressbar"
	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

// BypassModule defines the interface for all bypass modules
type BypassModule struct {
	Name         string
	payloadGen   *payload.PayloadGenerator
	GenerateJobs func(targetURL string, bypassMmode string, opts *ScannerOpts) []payload.BypassPayload
}

func NewBypassModule(name string) *BypassModule {
	return &BypassModule{
		Name:       name,
		payloadGen: payload.NewPayloadGenerator(),
	}
}

// Registry of all bypass modules
var bypassModules = map[string]*BypassModule{
	"dumb_check":                 NewBypassModule("dumb_check"),
	"mid_paths":                  NewBypassModule("mid_paths"),
	"end_paths":                  NewBypassModule("end_paths"),
	"http_headers_ip":            NewBypassModule("http_headers_ip"),
	"case_substitution":          NewBypassModule("case_substitution"),
	"char_encode":                NewBypassModule("char_encode"),
	"http_host":                  NewBypassModule("http_host"),
	"http_headers_scheme":        NewBypassModule("http_headers_scheme"),
	"http_headers_port":          NewBypassModule("http_headers_port"),
	"http_headers_url":           NewBypassModule("http_headers_url"),
	"unicode_path_normalization": NewBypassModule("unicode_path_normalization"),
}

// Registry of all bypass modules
func InitializeBypassModules() {
	for _, module := range bypassModules {
		module.payloadGen = payload.NewPayloadGenerator()

		switch module.Name {
		case "dumb_check":
			module.GenerateJobs = func(targetURL string, bypassModule string, opts *ScannerOpts) []payload.BypassPayload {
				return module.payloadGen.GenerateDumbCheckPayload(targetURL, bypassModule)
			}
		case "mid_paths":
			module.GenerateJobs = func(targetURL string, bypassModule string, opts *ScannerOpts) []payload.BypassPayload {
				return module.payloadGen.GenerateMidPathsPayloads(targetURL, bypassModule)
			}
		case "end_paths":
			module.GenerateJobs = func(targetURL string, bypassModule string, opts *ScannerOpts) []payload.BypassPayload {
				return module.payloadGen.GenerateEndPathsPayloads(targetURL, bypassModule)
			}
		case "http_headers_ip":
			module.GenerateJobs = func(targetURL string, bypassModule string, opts *ScannerOpts) []payload.BypassPayload {
				return module.payloadGen.GenerateHeaderIPPayloads(targetURL, bypassModule, opts.SpoofHeader, opts.SpoofIP)
			}
		case "case_substitution":
			module.GenerateJobs = func(targetURL string, bypassModule string, opts *ScannerOpts) []payload.BypassPayload {
				return module.payloadGen.GenerateCaseSubstitutionPayloads(targetURL, bypassModule)
			}
		case "char_encode":
			module.GenerateJobs = func(targetURL string, bypassModule string, opts *ScannerOpts) []payload.BypassPayload {
				return module.payloadGen.GenerateCharEncodePayloads(targetURL, bypassModule)
			}
		case "http_host":
			module.GenerateJobs = func(targetURL string, bypassModule string, opts *ScannerOpts) []payload.BypassPayload {
				return module.payloadGen.GenerateHostHeaderPayloads(targetURL, bypassModule, opts.ReconCache)
			}
		case "http_headers_scheme":
			module.GenerateJobs = func(targetURL string, bypassModule string, opts *ScannerOpts) []payload.BypassPayload {
				return module.payloadGen.GenerateHeaderSchemePayloads(targetURL, bypassModule)
			}
		case "http_headers_port":
			module.GenerateJobs = func(targetURL string, bypassModule string, opts *ScannerOpts) []payload.BypassPayload {
				return module.payloadGen.GenerateHeaderPortPayloads(targetURL, bypassModule)
			}
		case "http_headers_url":
			module.GenerateJobs = func(targetURL string, bypassModule string, opts *ScannerOpts) []payload.BypassPayload {
				return module.payloadGen.GenerateHeaderURLPayloads(targetURL, bypassModule)
			}
		case "unicode_path_normalization":
			module.GenerateJobs = func(targetURL string, bypassModule string, opts *ScannerOpts) []payload.BypassPayload {
				return module.payloadGen.GenerateUnicodePathNormalizationsPayloads(targetURL, bypassModule)
			}
		}
	}
}

type BypassWorker struct {
	bypassmodule string
	cancel       chan struct{}
	wg           *sync.WaitGroup
	once         sync.Once
	opts         *ScannerOpts
	requestPool  *rawhttp.RequestWorkerPool
	totalJobs    int
}

func NewBypassWorker(bypassmodule string, targetURL string, scannerOpts *ScannerOpts, totalJobs int) *BypassWorker {
	httpClientOpts := rawhttp.DefaultHTTPClientOptions()

	// Override specific settings from user options
	httpClientOpts.BypassModule = bypassmodule
	httpClientOpts.Timeout = time.Duration(scannerOpts.Timeout) * time.Millisecond
	httpClientOpts.ResponseBodyPreviewSize = scannerOpts.ResponseBodyPreviewSize

	// and proxy ofc
	httpClientOpts.ProxyURL = scannerOpts.Proxy

	// Apply a delay between requests
	if scannerOpts.RequestDelay > 0 {
		httpClientOpts.RequestDelay = time.Duration(scannerOpts.RequestDelay) * time.Millisecond
	}

	httpClientOpts.MaxRetries = scannerOpts.MaxRetries
	httpClientOpts.RetryDelay = time.Duration(scannerOpts.RetryDelay) * time.Millisecond
	httpClientOpts.MaxConsecutiveFailedReqs = scannerOpts.MaxConsecutiveFailedReqs

	httpClientOpts.AutoThrottle = scannerOpts.AutoThrottle

	// Disable streaming of response body if disabled via cli options
	if scannerOpts.DisableStreamResponseBody {
		httpClientOpts.StreamResponseBody = false
	}

	return &BypassWorker{
		bypassmodule: bypassmodule,
		cancel:       make(chan struct{}),
		wg:           &sync.WaitGroup{},
		once:         sync.Once{},
		opts:         scannerOpts,
		totalJobs:    totalJobs,
		requestPool:  rawhttp.NewRequestWorkerPool(httpClientOpts, scannerOpts.Threads),
	}
}

// Stop the BypassWorkerContext
// Also close the requestworkerpool
func (w *BypassWorker) Stop() {
	w.once.Do(func() {
		select {
		case <-w.cancel:
			return
		default:
			close(w.cancel)
			if w.requestPool != nil {
				w.requestPool.Close()
			}
		}
	})
}

// Core Function
func (s *Scanner) RunAllBypasses(targetURL string) int {
	totalFindings := 0

	modules := strings.Split(s.scannerOpts.BypassModule, ",")
	for _, module := range modules {
		module = strings.TrimSpace(module)
		if module == "" {
			continue
		}

		// Now RunBypassModule returns count instead of using channels
		findings := s.RunBypassModule(module, targetURL)
		totalFindings += findings
	}

	return totalFindings
}

// Run a specific Bypass Module and return the number of findings
// func (s *Scanner) RunBypassModule(bypassModule string, targetURL string) int {
// 	moduleInstance, exists := bypassModules[bypassModule]
// 	if !exists {
// 		return 0
// 	}

// 	allJobs := moduleInstance.GenerateJobs(targetURL, bypassModule, s.scannerOpts)
// 	if len(allJobs) == 0 {
// 		GB403Logger.Warning().Msgf("No jobs generated for bypass module: %s\n", bypassModule)
// 		return 0
// 	}

// 	GB403Logger.Info().Msgf("[%s] Generated %d payloads for %s\n", bypassModule, len(allJobs), targetURL)

// 	worker := NewBypassWorker(bypassModule, targetURL, s.scannerOpts, len(allJobs))
// 	defer worker.Stop()

// 	var progressBar *ProgressBar
// 	if s.progressBarEnabled.Load() {
// 		progressBar = NewProgressBar(bypassModule, targetURL, len(allJobs), s.scannerOpts.Threads)
// 		progressBar.Start()
// 		defer progressBar.Stop()
// 	}

// 	responses := worker.requestPool.ProcessRequests(allJobs)

// 	var dbWg sync.WaitGroup
// 	resultCount := atomic.Int32{}

// 	// Process responses and update progress based on pool metrics
// 	for response := range responses {
// 		if response == nil {
// 			continue
// 		}

// 		// Update progress bar to match pool state
// 		if progressBar != nil {
// 			progressBar.Increment()
// 			progressBar.UpdateSpinnerText(
// 				worker.requestPool.GetReqWPActiveWorkers(),
// 				worker.requestPool.GetReqWPCompletedTasks(),
// 				worker.requestPool.GetReqWPSubmittedTasks(),
// 				worker.requestPool.GetRequestRate(),
// 				worker.requestPool.GetAverageRequestRate(),
// 			)
// 		}

// 		if matchStatusCodes(response.StatusCode, s.scannerOpts.MatchStatusCodes) {
// 			// Create Result struct from response
// 			result := &Result{
// 				TargetURL:           string(response.URL),
// 				BypassModule:        string(response.BypassModule),
// 				StatusCode:          response.StatusCode,
// 				ResponseHeaders:     string(response.ResponseHeaders),
// 				CurlCMD:             string(response.CurlCommand),
// 				ResponseBodyPreview: string(response.ResponsePreview),
// 				ContentType:         string(response.ContentType),
// 				ContentLength:       response.ContentLength,
// 				ResponseBodyBytes:   response.ResponseBytes,
// 				Title:               string(response.Title),
// 				ServerInfo:          string(response.ServerInfo),
// 				RedirectURL:         string(response.RedirectURL),
// 				ResponseTime:        response.ResponseTime,
// 				DebugToken:          string(response.DebugToken),
// 			}

// 			// Write to DB in a separate goroutine
// 			dbWg.Add(1)
// 			go func(res *Result) {
// 				defer dbWg.Done()
// 				if err := AppendResultsToDB([]*Result{res}); err != nil {
// 					GB403Logger.Error().Msgf("Failed to write result to DB: %v\n\n", err)
// 				} else {
// 					resultCount.Add(1) // Only increment on successful DB write
// 				}
// 			}(result)
// 		}

// 		// Release the RawHTTPResponseDetails back to its pool
// 		rawhttp.ReleaseResponseDetails(response)
// 	}

// 	// Before function returns, wait for all DB operations to complete
// 	dbWg.Wait()

// 	if progressBar != nil {
// 		// Check if module was cancelled by comparing completed vs total jobs
// 		completedTasks := worker.requestPool.GetReqWPCompletedTasks()

// 		// If we didn't complete all jobs, it was likely cancelled
// 		if completedTasks < uint64(len(allJobs)) {
// 			progressBar.SpinnerFailed(
// 				completedTasks,
// 				uint64(len(allJobs)),
// 				worker.requestPool.GetAverageRequestRate(),
// 				worker.requestPool.GetPeakRequestRate(),
// 			)
// 		} else {
// 			// Normal completion - show success spinner
// 			progressBar.SpinnerSuccess(
// 				worker.requestPool.GetReqWPCompletedTasks(),
// 				worker.requestPool.GetReqWPSubmittedTasks(),
// 				worker.requestPool.GetAverageRequestRate(),
// 				worker.requestPool.GetPeakRequestRate(),
// 			)
// 		}
// 	}

// 	return int(resultCount.Load())
// }

func (s *Scanner) RunBypassModule(bypassModule string, targetURL string) int {
	moduleInstance, exists := bypassModules[bypassModule]
	if !exists {
		return 0
	}

	allJobs := moduleInstance.GenerateJobs(targetURL, bypassModule, s.scannerOpts)
	totalJobs := len(allJobs)
	if totalJobs == 0 {
		GB403Logger.Warning().Msgf("No jobs generated for bypass module: %s\n", bypassModule)
		return 0
	}

	GB403Logger.Info().Msgf("[%s] Generated %d payloads for %s\n", bypassModule, totalJobs, targetURL)

	worker := NewBypassWorker(bypassModule, targetURL, s.scannerOpts, totalJobs)
	defer worker.Stop()

	maxWorkers := s.scannerOpts.Threads
	// Create new progress bar configuration
	cfg := progressbar.DefaultConfig()
	cfg.Prefix = bypassModule
	cfg.UseColors = true
	cfg.Color = progressbar.GreenBar
	//cfg.ScreenWriter = os.Stderr
	//cfg.UpdateInterval = 100 // * time.Millisecond

	// Create new progress bar
	bar := cfg.NewBar()

	responses := worker.requestPool.ProcessRequests(allJobs)
	var dbWg sync.WaitGroup
	resultCount := atomic.Int32{}

	for response := range responses {
		if response == nil {
			continue
		}

		// Update progress bar with current stats
		completed := worker.requestPool.GetReqWPCompletedTasks()
		active := worker.requestPool.GetReqWPActiveWorkers()
		currentRate := worker.requestPool.GetRequestRate()
		avgRate := worker.requestPool.GetAverageRequestRate()

		msg := fmt.Sprintf(
			"Workers [%d/%d] | Rate [%d req/s] Avg [%d req/s] | Completed %d/%d --",
			active, maxWorkers, currentRate, avgRate, completed, uint64(totalJobs),
		)
		bar.WriteAbove(msg)

		if matchStatusCodes(response.StatusCode, s.scannerOpts.MatchStatusCodes) {
			if s.scannerOpts.MatchContentType != "" {
				contentType := strings.ToLower(string(response.ContentType))
				if !strings.Contains(contentType, strings.ToLower(s.scannerOpts.MatchContentType)) {
					continue
				}
			}

			result := &Result{
				TargetURL:           string(response.URL),
				BypassModule:        string(response.BypassModule),
				StatusCode:          response.StatusCode,
				ResponseHeaders:     string(response.ResponseHeaders),
				CurlCMD:             string(response.CurlCommand),
				ResponseBodyPreview: string(response.ResponsePreview),
				ContentType:         string(response.ContentType),
				ContentLength:       response.ContentLength,
				ResponseBodyBytes:   response.ResponseBytes,
				Title:               string(response.Title),
				ServerInfo:          string(response.ServerInfo),
				RedirectURL:         string(response.RedirectURL),
				ResponseTime:        response.ResponseTime,
				DebugToken:          string(response.DebugToken),
			}

			dbWg.Add(1)
			go func(res *Result) {
				defer dbWg.Done()
				if err := AppendResultsToDB([]*Result{res}); err != nil {
					GB403Logger.Error().Msgf("Failed to write result to DB: %v\n\n", err)
				} else {
					resultCount.Add(1)
				}
			}(result)
		}

		rawhttp.ReleaseResponseDetails(response)

		progressPercent := (float64(completed) / float64(totalJobs)) * 100.0
		if progressPercent > 100.0 {
			progressPercent = 100.0
		}
		bar.Progress(progressPercent)
	}

	dbWg.Wait()
	bar.End()
	fmt.Println()

	return int(resultCount.Load())
}

// ResendRequestFromToken
// Resend a request from a payload token (debug token)
func (s *Scanner) ResendRequestFromToken(debugToken string, resendCount int) ([]*Result, error) {
	tokenData, err := payload.DecodePayloadToken(debugToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode debug token: %w", err)
	}

	bypassPayload := payload.BypassPayload{
		OriginalURL:  tokenData.OriginalURL,
		Method:       tokenData.Method,
		Scheme:       tokenData.Scheme,
		Host:         tokenData.Host,
		RawURI:       tokenData.RawURI,
		Headers:      tokenData.Headers,
		BypassModule: tokenData.BypassModule,
	}

	targetURL := payload.BypassPayloadToBaseURL(bypassPayload)

	// Create a new worker for the bypass module
	worker := NewBypassWorker(bypassPayload.BypassModule, targetURL, s.scannerOpts, resendCount)
	defer worker.Stop()

	// Create jobs array with pre-allocated capacity
	jobs := make([]payload.BypassPayload, 0, resendCount)
	for i := 0; i < resendCount; i++ {
		jobCopy := bypassPayload // Create a copy to avoid sharing the same job reference
		jobCopy.PayloadToken = payload.GeneratePayloadToken(bypassPayload)
		jobs = append(jobs, jobCopy)
	}

	var progressBar *ProgressBar
	if s.progressBarEnabled.Load() {
		progressBar = NewProgressBar(bypassPayload.BypassModule, targetURL, resendCount, s.scannerOpts.Threads)
		progressBar.Start()
		defer progressBar.Stop()
	}

	responses := worker.requestPool.ProcessRequests(jobs)
	var results []*Result

	for response := range responses {
		if response == nil {
			continue
		}

		// Update progress
		if progressBar != nil {
			progressBar.Increment()
			progressBar.UpdateSpinnerText(
				worker.requestPool.GetReqWPActiveWorkers(),
				worker.requestPool.GetReqWPCompletedTasks(),
				worker.requestPool.GetReqWPSubmittedTasks(),
				worker.requestPool.GetRequestRate(),
				worker.requestPool.GetAverageRequestRate(),
			)
		}

		// Only add to results if status code matches
		if matchStatusCodes(response.StatusCode, s.scannerOpts.MatchStatusCodes) {
			result := &Result{
				TargetURL:           targetURL,
				BypassModule:        string(response.BypassModule),
				StatusCode:          response.StatusCode,
				ResponseHeaders:     string(response.ResponseHeaders),
				CurlCMD:             string(response.CurlCommand),
				ResponseBodyPreview: string(response.ResponsePreview),
				ContentType:         string(response.ContentType),
				ContentLength:       response.ContentLength,
				ResponseBodyBytes:   response.ResponseBytes,
				Title:               string(response.Title),
				ServerInfo:          string(response.ServerInfo),
				RedirectURL:         string(response.RedirectURL),
				ResponseTime:        response.ResponseTime,
				DebugToken:          string(response.DebugToken),
			}

			results = append(results, result)
		}

		// Release the response object immediately after processing - for all responses
		rawhttp.ReleaseResponseDetails(response)
	}

	// Final progress update
	if progressBar != nil {
		progressBar.SpinnerSuccess(
			worker.requestPool.GetReqWPCompletedTasks(),
			worker.requestPool.GetReqWPSubmittedTasks(),
			worker.requestPool.GetAverageRequestRate(),
			worker.requestPool.GetPeakRequestRate(),
		)
	}

	return results, nil
}

// match HTTP status code in list
// if codes is nil, match all status codes
func matchStatusCodes(code int, codes []int) bool {
	if codes == nil { // Still need explicit nil check
		return true
	}
	return slices.Contains(codes, code) // Different behavior for empty vs nil slices
}
