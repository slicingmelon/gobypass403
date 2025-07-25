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
	"github.com/slicingmelon/gobypass403/core/utils/helpers"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

// Global map to track already seen RawURIs across all bypass modules
var (
	seenRawURIsMutex sync.RWMutex
	seenRawURIs      = make(map[string]string) // map[rawURI]bypassModule
)

// FilterUniqueBypassPayloads removes payloads with RawURIs that have been seen before across modules
func FilterUniqueBypassPayloads(payloads []payload.BypassPayload, bypassModule string) []payload.BypassPayload {
	// Check if this module should be filtered
	modulesToFilter := map[string]bool{
		"case_substitution":          true,
		"char_encode":                true,
		"end_paths":                  true,
		"mid_paths":                  true,
		"nginx_bypasses":             true,
		"path_prefix":                true,
		"unicode_path_normalization": true,
	}

	if !modulesToFilter[bypassModule] {
		return payloads
	}

	filtered := make([]payload.BypassPayload, 0, len(payloads))

	seenRawURIsMutex.RLock()
	initialSize := len(seenRawURIs)
	seenRawURIsMutex.RUnlock()

	for _, p := range payloads {
		seenRawURIsMutex.RLock()
		previousModule, seen := seenRawURIs[p.RawURI]
		seenRawURIsMutex.RUnlock()

		// Add payloads that are globally unique or belong to this module
		if !seen || previousModule == bypassModule {
			// Add to filtered list
			filtered = append(filtered, p)

			// Update global map
			if !seen {
				seenRawURIsMutex.Lock()
				seenRawURIs[p.RawURI] = bypassModule
				seenRawURIsMutex.Unlock()
			}
		}
	}

	seenRawURIsMutex.RLock()
	newSize := len(seenRawURIs)
	seenRawURIsMutex.RUnlock()

	// Calculate new unique RawURIs added
	addedURIs := newSize - initialSize

	GB403Logger.Verbose().Msgf("[%s] Filtered payloads: %d -> %d | Global RawURIs: %d -> %d (%d new unique)",
		bypassModule, len(payloads), len(filtered), initialSize, newSize, addedURIs)

	return filtered
}

// IsValidBypassModule checks if a module is valid
func IsValidBypassModule(moduleName string) bool {
	return slices.Contains(payload.BypassModulesRegistry, moduleName)
}

type BypassEngagement struct {
	bypassmodule string
	once         sync.Once
	opts         *ScannerOpts
	requestPool  *rawhttp.RequestWorkerPool
	totalJobs    int
}

func NewBypassEngagement(bypassmodule string, targetURL string, scannerOpts *ScannerOpts, totalJobs int) *BypassEngagement {
	httpClientOpts := rawhttp.DefaultHTTPClientOptions()

	// Override specific settings from user options
	httpClientOpts.BypassModule = bypassmodule
	httpClientOpts.Timeout = time.Duration(scannerOpts.Timeout) * time.Millisecond

	// Set response body preview size - buffer adjustments handled in NewHTTPClient
	httpClientOpts.ResponseBodyPreviewSize = scannerOpts.ResponseBodyPreviewSize

	// and proxy ofc
	httpClientOpts.ProxyURL = scannerOpts.Proxy

	// Pass custom HTTP headers to client options
	httpClientOpts.CustomHTTPHeaders = scannerOpts.CustomHTTPHeaders

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

	// Adjust MaxConnsPerHost based on max concurrent requests
	// Add 50% more connections than workers for buffer, ensure it's at least the default
	maxConcurrentReqs := scannerOpts.ConcurrentRequests
	calculatedMaxConns := maxConcurrentReqs + (maxConcurrentReqs / 2)
	if calculatedMaxConns > httpClientOpts.MaxConnsPerHost {
		httpClientOpts.MaxConnsPerHost = calculatedMaxConns
	}

	return &BypassEngagement{
		bypassmodule: bypassmodule,
		once:         sync.Once{},
		opts:         scannerOpts,
		totalJobs:    totalJobs,
		requestPool:  rawhttp.NewRequestWorkerPool(httpClientOpts, scannerOpts.ConcurrentRequests),
	}
}

// Stop the BypassEngagement
// Also close the requestworkerpool
func (w *BypassEngagement) Stop() {
	w.once.Do(func() {
		if w.requestPool != nil {
			w.requestPool.Close()
		}
	})
}

// ResetSeenRawURIs clears the global map of seen RawURIs
func ResetSeenRawURIs() {
	seenRawURIsMutex.Lock()
	defer seenRawURIsMutex.Unlock()

	// Create a new map rather than clearing the existing one
	// This is more efficient for large maps
	seenRawURIs = make(map[string]string)
	GB403Logger.Verbose().Msgf("Reset global RawURI tracking map\n")
}

// Core Function
func (s *Scanner) RunAllBypasses(targetURL string) int {
	totalFindings := 0

	// Reset the global seen RawURIs map for this new target URL
	ResetSeenRawURIs()

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

	// Filter unique payloads based on RawURI
	allJobs = FilterUniqueBypassPayloads(allJobs, bypassModule)

	totalJobs := len(allJobs)
	if totalJobs == 0 {
		GB403Logger.Warning().Msgf("No jobs generated for bypass module: %s\n", bypassModule)
		return 0
	}

	GB403Logger.PrintBypassModuleInfo(bypassModule, totalJobs, targetURL)

	maxModuleNameLength := 0
	for _, module := range payload.BypassModulesRegistry {
		if len(module) > maxModuleNameLength {
			maxModuleNameLength = len(module)
		}
	}

	worker := NewBypassEngagement(bypassModule, targetURL, s.scannerOpts, totalJobs)
	defer worker.Stop()

	maxConcurrentReqs := s.scannerOpts.ConcurrentRequests

	// Create formatted prefix with padding
	prefix := bypassModule + strings.Repeat(" ", maxModuleNameLength-len(bypassModule)+1)
	// Create new progress bar
	bar := NewProgressBar(prefix, progressbar.RedBar, 1, &s.progressBarEnabled)

	responses := worker.requestPool.ProcessRequests(allJobs)
	var dbWg sync.WaitGroup
	resultCount := atomic.Int32{}

	for response := range responses {
		if response == nil {
			continue
		}

		// Update progress bar stats here
		completed := worker.requestPool.GetReqWPCompletedTasks()
		currentRate := worker.requestPool.GetRequestRate()
		avgRate := worker.requestPool.GetAverageRequestRate()

		msg := fmt.Sprintf(
			"Max Concurrent [%d req] | Rate [%d req/s] Avg [%d req/s] | Completed %d/%d    ",
			maxConcurrentReqs, currentRate, avgRate, completed, uint64(totalJobs),
		)
		bar.WriteAbove(msg)

		// Check status code - if no match, skip
		if !matchStatusCodes(response.StatusCode, s.scannerOpts.MatchStatusCodes) {
			rawhttp.ReleaseResponseDetails(response)
			bar.Progress((float64(completed) / float64(totalJobs)) * 100.0)
			continue
		}

		// Check content type if required
		if len(s.scannerOpts.MatchContentTypeBytes) > 0 {
			contentTypeMatched := false
			for _, matchType := range s.scannerOpts.MatchContentTypeBytes {
				if bytes.Contains(response.ContentType, matchType) {
					contentTypeMatched = true
					break
				}
			}
			if !contentTypeMatched {
				rawhttp.ReleaseResponseDetails(response)
				bar.Progress((float64(completed) / float64(totalJobs)) * 100.0)
				continue
			}
		}

		// Check min content length
		if s.scannerOpts.MinContentLength > 0 {
			if response.ContentLength < 0 || response.ContentLength < int64(s.scannerOpts.MinContentLength) {
				rawhttp.ReleaseResponseDetails(response)
				bar.Progress((float64(completed) / float64(totalJobs)) * 100.0)
				continue
			}
		}

		// Check max content length
		if s.scannerOpts.MaxContentLength > 0 && response.ContentLength >= 0 {
			if response.ContentLength > int64(s.scannerOpts.MaxContentLength) {
				rawhttp.ReleaseResponseDetails(response)
				bar.Progress((float64(completed) / float64(totalJobs)) * 100.0)
				continue
			}
		}

		// Process valid result
		result := &Result{
			TargetURL:           string(response.URL),
			BypassModule:        string(response.BypassModule),
			StatusCode:          response.StatusCode,
			ResponseHeaders:     helpers.SanitizeNonPrintableBytes(response.ResponseHeaders),
			CurlCMD:             helpers.SanitizeNonPrintableBytes(response.CurlCommand),
			ResponseBodyPreview: string(response.ResponsePreview),
			ContentType:         string(response.ContentType),
			ContentLength:       response.ContentLength,
			ResponseBodyBytes:   response.ResponseBytes,
			Title:               string(response.Title),
			ServerInfo:          string(response.ServerInfo),
			RedirectURL:         helpers.SanitizeNonPrintableBytes(response.RedirectURL),
			ResponseTime:        response.ResponseTime,
			DebugToken:          string(response.DebugToken),
		}

		rawhttp.ReleaseResponseDetails(response)
		progressPercent := (float64(completed) / float64(totalJobs)) * 100.0
		progressPercent = min(progressPercent, 100.0)
		bar.Progress(progressPercent)

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

	bar.End()
	fmt.Println()

	dbWg.Wait()

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
	totalJobs := resendCount // Total jobs for the progress bar

	// Update concurrent requets to 1
	s.scannerOpts.ConcurrentRequests = 1

	// Create a new worker for the bypass module
	worker := NewBypassEngagement(bypassPayload.BypassModule, targetURL, s.scannerOpts, totalJobs)
	defer worker.Stop()

	jobs := make([]payload.BypassPayload, 0, totalJobs)
	for i := 0; i < totalJobs; i++ {
		jobCopy := bypassPayload // Create a copy to avoid sharing the same job reference
		jobCopy.PayloadToken = payload.GeneratePayloadToken(bypassPayload)
		jobs = append(jobs, jobCopy)
	}

	// Create formatted prefix
	prefix := fmt.Sprintf("[Resend] %s", bypassPayload.BypassModule)
	// Create new progress bar with wrapper - simplified
	bar := NewProgressBar(prefix, progressbar.BlueBar, 1, &s.progressBarEnabled)
	bar.Progress(0)

	responses := worker.requestPool.ProcessRequests(jobs)
	var results []*Result

	for response := range responses {
		completed := worker.requestPool.GetReqWPCompletedTasks()

		if response == nil {
			progressPercent := (float64(completed) / float64(totalJobs)) * 100.0
			progressPercent = min(progressPercent, 100.0)
			bar.Progress(progressPercent)
			continue
		}

		// Process Valid Response
		if matchStatusCodes(response.StatusCode, s.scannerOpts.MatchStatusCodes) {
			result := &Result{
				TargetURL:           targetURL,
				BypassModule:        string(response.BypassModule),
				StatusCode:          response.StatusCode,
				ResponseHeaders:     helpers.SanitizeNonPrintableBytes(response.ResponseHeaders),
				CurlCMD:             helpers.SanitizeNonPrintableBytes(response.CurlCommand),
				ResponseBodyPreview: string(response.ResponsePreview),
				ContentType:         string(response.ContentType),
				ContentLength:       response.ContentLength,
				ResponseBodyBytes:   response.ResponseBytes,
				Title:               string(response.Title),
				ServerInfo:          string(response.ServerInfo),
				RedirectURL:         helpers.SanitizeNonPrintableBytes(response.RedirectURL),
				ResponseTime:        response.ResponseTime,
				DebugToken:          string(response.DebugToken),
			}
			results = append(results, result)
		}

		rawhttp.ReleaseResponseDetails(response)

		currentRate := worker.requestPool.GetRequestRate()
		avgRate := worker.requestPool.GetAverageRequestRate()
		maxConcurrentReqs := s.scannerOpts.ConcurrentRequests

		msg := fmt.Sprintf(
			"Max Concurrent [%d req] | Rate [%d req/s] Avg [%d req/s] | Completed %d/%d    ",
			maxConcurrentReqs, currentRate, avgRate, completed, uint64(totalJobs),
		)
		bar.WriteAbove(msg)

		progressPercent := (float64(completed) / float64(totalJobs)) * 100.0
		progressPercent = min(progressPercent, 100.0)
		bar.Progress(progressPercent)
	}

	finalCompleted := worker.requestPool.GetReqWPCompletedTasks()

	// Calculate the final, accurate progress percentage
	finalProgressPercent := (float64(finalCompleted) / float64(totalJobs)) * 100.0
	finalProgressPercent = min(finalProgressPercent, 100.0)
	bar.Progress(finalProgressPercent)
	bar.End()

	fmt.Println()

	return results, nil
}

// match HTTP status code in list
// if codes is nil, match all status codes
func matchStatusCodes(code int, codes []int) bool {
	if codes == nil { // Still need nil check
		return true
	}
	return slices.Contains(codes, code)
}
