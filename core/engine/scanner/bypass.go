/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package scanner

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fortio.org/progressbar"
	"github.com/slicingmelon/gobypass403/core/engine/payload"
	"github.com/slicingmelon/gobypass403/core/engine/rawhttp"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

// Registry of all bypass modules
var AvailableBypassModules = []string{
	"dumb_check",
	"mid_paths",
	"end_paths",
	"http_methods",
	"case_substitution",
	"char_encode",
	"nginx_bypasses",
	"http_headers_ip",
	"http_host",
	"http_headers_scheme",
	"http_headers_port",
	"http_headers_url",
	"unicode_path_normalization",
}

// IsValidBypassModule checks if a module is valid
func IsValidBypassModule(moduleName string) bool {
	for _, module := range AvailableBypassModules {
		if module == moduleName {
			return true
		}
	}
	return false
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
func (s *Scanner) RunBypassModule(bypassModule string, targetURL string) int {
	if !IsValidBypassModule(bypassModule) {
		GB403Logger.Error().Msgf("Invalid bypass module: %s\n", bypassModule)
		return 0
	}

	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: bypassModule,
		ReconCache:   s.scannerOpts.ReconCache,
		SpoofHeader:  s.scannerOpts.SpoofHeader,
		SpoofIP:      s.scannerOpts.SpoofIP,
	})

	allJobs := pg.Generate()

	totalJobs := len(allJobs)
	if totalJobs == 0 {
		GB403Logger.Warning().Msgf("No jobs generated for bypass module: %s\n", bypassModule)
		return 0
	}

	//GB403Logger.Info().Msgf("[%s] Generated %d payloads for %s\n", bypassModule, totalJobs, targetURL)
	GB403Logger.PrintBypassModuleInfo(bypassModule, totalJobs, targetURL)

	maxModuleNameLength := 0
	for _, module := range AvailableBypassModules {
		if len(module) > maxModuleNameLength {
			maxModuleNameLength = len(module)
		}
	}

	worker := NewBypassWorker(bypassModule, targetURL, s.scannerOpts, totalJobs)
	defer worker.Stop()

	maxWorkers := s.scannerOpts.Threads
	// Create new progress bar configuration
	cfg := progressbar.DefaultConfig()
	//cfg.Prefix = bypassModule
	cfg.Prefix = bypassModule + strings.Repeat(" ", maxModuleNameLength-len(bypassModule))
	cfg.UseColors = true
	cfg.ExtraLines = 1

	cfg.Color = progressbar.RedBar
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
		//active := worker.requestPool.GetReqWPActiveWorkers()
		currentRate := worker.requestPool.GetRequestRate()
		avgRate := worker.requestPool.GetAverageRequestRate()

		// weird bug "overflowing" on the text above the progressbar ... spaces fixes it
		msg := fmt.Sprintf(
			"Max Concurrent [%d req] | Rate [%d req/s] Avg [%d req/s] | Completed %d/%d    ",
			maxWorkers, currentRate, avgRate, completed, uint64(totalJobs),
		)
		bar.WriteAbove(msg)

		if matchStatusCodes(response.StatusCode, s.scannerOpts.MatchStatusCodes) {
			if len(s.scannerOpts.MatchContentTypeBytes) > 0 {
				contentTypeMatched := false
				for _, matchType := range s.scannerOpts.MatchContentTypeBytes {
					if bytes.Contains(response.ContentType, matchType) {
						contentTypeMatched = true
						break
					}
				}
				if !contentTypeMatched {
					continue // Skip this response
				}
			}

			result := &Result{
				TargetURL:    string(response.URL),
				BypassModule: string(response.BypassModule),
				StatusCode:   response.StatusCode,
				//ResponseHeaders:     string(response.ResponseHeaders),
				ResponseHeaders:     sanitizeNonPrintableBytes(response.ResponseHeaders),
				CurlCMD:             sanitizeNonPrintableBytes(response.CurlCommand),
				ResponseBodyPreview: string(response.ResponsePreview),
				ContentType:         string(response.ContentType),
				ContentLength:       response.ContentLength,
				ResponseBodyBytes:   response.ResponseBytes,
				Title:               string(response.Title),
				ServerInfo:          string(response.ServerInfo),
				RedirectURL:         sanitizeNonPrintableBytes(response.RedirectURL),
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
				ResponseHeaders:     sanitizeNonPrintableBytes(response.ResponseHeaders),
				CurlCMD:             sanitizeNonPrintableBytes(response.CurlCommand),
				ResponseBodyPreview: string(response.ResponsePreview),
				ContentType:         string(response.ContentType),
				ContentLength:       response.ContentLength,
				ResponseBodyBytes:   response.ResponseBytes,
				Title:               string(response.Title),
				ServerInfo:          string(response.ServerInfo),
				RedirectURL:         sanitizeNonPrintableBytes(response.RedirectURL),
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

func sanitizeNonPrintableBytes(input []byte) string {
	var sb strings.Builder
	sb.Grow(len(input))

	for _, b := range input {
		// Keep printable ASCII (32-126), LF (10), CR (13)
		if (b >= 32 && b <= 126) || b == 10 || b == 13 {
			sb.WriteByte(b)
			// Explicitly handle Tab separately and
			// replace with its escape sequence -- to test
		} else if b == 9 {
			sb.WriteString("\\x09")
		} else {
			// Replace others with Go-style hex escape
			sb.WriteString(fmt.Sprintf("\\x%02x", b))
		}
	}
	return sb.String()
}
