package scanner

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"time"

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
				return module.payloadGen.GenerateDumbJob(targetURL, bypassModule)
			}
		case "mid_paths":
			module.GenerateJobs = func(targetURL string, bypassModule string, opts *ScannerOpts) []payload.BypassPayload {
				return module.payloadGen.GenerateMidPathsJobs(targetURL, bypassModule)
			}
		case "end_paths":
			module.GenerateJobs = func(targetURL string, bypassModule string, opts *ScannerOpts) []payload.BypassPayload {
				return module.payloadGen.GenerateEndPathsJobs(targetURL, bypassModule)
			}
		case "http_headers_ip":
			module.GenerateJobs = func(targetURL string, bypassModule string, opts *ScannerOpts) []payload.BypassPayload {
				return module.payloadGen.GenerateHeaderIPJobs(targetURL, bypassModule, opts.SpoofHeader, opts.SpoofIP)
			}
		case "case_substitution":
			module.GenerateJobs = func(targetURL string, bypassModule string, opts *ScannerOpts) []payload.BypassPayload {
				return module.payloadGen.GenerateCaseSubstitutionJobs(targetURL, bypassModule)
			}
		case "char_encode":
			module.GenerateJobs = func(targetURL string, bypassModule string, opts *ScannerOpts) []payload.BypassPayload {
				return module.payloadGen.GenerateCharEncodeJobs(targetURL, bypassModule)
			}
		case "http_host":
			module.GenerateJobs = func(targetURL string, bypassModule string, opts *ScannerOpts) []payload.BypassPayload {
				return module.payloadGen.GenerateHostHeaderJobs(targetURL, bypassModule, opts.ReconCache)
			}
		case "http_headers_scheme":
			module.GenerateJobs = func(targetURL string, bypassModule string, opts *ScannerOpts) []payload.BypassPayload {
				return module.payloadGen.GenerateHeaderSchemeJobs(targetURL, bypassModule)
			}
		case "http_headers_port":
			module.GenerateJobs = func(targetURL string, bypassModule string, opts *ScannerOpts) []payload.BypassPayload {
				return module.payloadGen.GenerateHeaderPortJobs(targetURL, bypassModule)
			}
		case "http_headers_url":
			module.GenerateJobs = func(targetURL string, bypassModule string, opts *ScannerOpts) []payload.BypassPayload {
				return module.payloadGen.GenerateHeaderURLJobs(targetURL, bypassModule)
			}
		case "unicode_path_normalization":
			module.GenerateJobs = func(targetURL string, bypassModule string, opts *ScannerOpts) []payload.BypassPayload {
				return module.payloadGen.GenerateUnicodePathNormalizationsJobs(targetURL, bypassModule)
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
	progressBar  *ProgressBar
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
func (s *Scanner) RunAllBypasses(targetURL string) chan *Result {
	results := make(chan *Result)

	go func() {
		defer close(results)

		modules := strings.Split(s.scannerOpts.BypassModule, ",")
		for _, module := range modules {
			module = strings.TrimSpace(module)
			if module == "" {
				continue
			}

			modResults := make(chan *Result)
			go s.RunBypassModule(module, targetURL, modResults)

			// Just forward results for progress tracking
			for res := range modResults {
				if res != nil {
					results <- res
				}
			}
		}
	}()

	return results
}

var resultsBufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// Run a specific Bypass Module
func (s *Scanner) RunBypassModule(bypassModule string, targetURL string, results chan<- *Result) {
	defer close(results)

	moduleInstance, exists := bypassModules[bypassModule]
	if !exists {
		return
	}

	allJobs := moduleInstance.GenerateJobs(targetURL, bypassModule, s.scannerOpts)
	if len(allJobs) == 0 {
		GB403Logger.Warning().Msgf("No jobs generated for bypass module: %s\n", bypassModule)
		return
	}

	GB403Logger.Verbose().Msgf("[%s] Generated %d payloads for %s\n", bypassModule, len(allJobs), targetURL)

	worker := NewBypassWorker(bypassModule, targetURL, s.scannerOpts, len(allJobs))
	defer worker.Stop()

	var progressBar *ProgressBar
	if !s.scannerOpts.DisableProgressBar {
		progressBar = NewProgressBar(bypassModule, len(allJobs), s.scannerOpts.Threads)
		progressBar.Start()
		defer progressBar.Stop()
	}

	responses := worker.requestPool.ProcessRequests(allJobs)

	// Process responses and update progress based on pool metrics
	for response := range responses {
		if response == nil {
			continue
		}

		// Update progress bar to match pool state
		if !s.scannerOpts.DisableProgressBar {
			progressBar.Increment()
			progressBar.UpdateSpinnerText(
				bypassModule,
				s.scannerOpts.Threads,
				worker.requestPool.GetReqWPActiveWorkers(),
				worker.requestPool.GetReqWPCompletedTasks(),
				worker.requestPool.GetReqWPSubmittedTasks(),
				worker.requestPool.GetRequestRate(),
				worker.requestPool.GetAverageRequestRate(),
			)
		}

		if matchStatusCodes(response.StatusCode, s.scannerOpts.MatchStatusCodes) {
			buf := resultsBufferPool.Get().(*bytes.Buffer)
			buf.Reset()

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

			// Write to file immediately
			if err := AppendResultsToJsonL(GetResultsFile(), []*Result{result}); err != nil {
				GB403Logger.Error().Msgf("Failed to write result: %v\n", err)
			}

			results <- result
			resultsBufferPool.Put(buf)
		}
	}

	// Final success state
	if !s.scannerOpts.DisableProgressBar {
		progressBar.SpinnerSuccess(
			bypassModule,
			s.scannerOpts.Threads,
			0,
			worker.requestPool.GetReqWPCompletedTasks(),
			worker.requestPool.GetReqWPSubmittedTasks(),
			worker.requestPool.GetRequestRate(),
			worker.requestPool.GetAverageRequestRate(),
			worker.requestPool.GetPeakRequestRate(),
		)
	}
}

func (s *Scanner) ResendRequestWithToken(debugToken string, resendCount int) ([]*Result, error) {
	// Parse URL from token
	tokenData, err := payload.DecodeDebugToken(debugToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode debug token: %w", err)
	}

	// Create base job
	job := payload.BypassPayload{
		OriginalURL:  tokenData.OriginalURL, // kept for compatibility
		Method:       tokenData.Method,
		Scheme:       tokenData.Scheme,
		Host:         tokenData.Host,
		RawURI:       tokenData.RawURI,
		Headers:      tokenData.Headers,
		BypassModule: "debugRequest",
	}

	// Construct display URL for logging/display purposes only
	displayURL := fmt.Sprintf("%s://%s%s", tokenData.Scheme, tokenData.Host, tokenData.RawURI)

	worker := NewBypassWorker("debugRequest", displayURL, s.scannerOpts, resendCount)
	defer worker.Stop()

	// Create jobs array with pre-allocated capacity
	jobs := make([]payload.BypassPayload, 0, resendCount)
	for i := 0; i < resendCount; i++ {
		jobCopy := job // Create a copy to avoid sharing the same job reference
		jobCopy.PayloadToken = payload.GenerateDebugToken(payload.SeedData{
			Method:  tokenData.Method,
			Scheme:  tokenData.Scheme,
			Host:    tokenData.Host,
			RawURI:  tokenData.RawURI,
			Headers: tokenData.Headers,
		})
		jobs = append(jobs, jobCopy)
	}

	progressbar := NewProgressBar("debugRequest", len(jobs), s.scannerOpts.Threads)
	progressbar.Start()
	defer progressbar.Stop()

	responses := worker.requestPool.ProcessRequests(jobs)
	var results []*Result

	for response := range responses {
		if response == nil {
			continue
		}

		// Ensure release happens even if processing panics
		defer func(resp *rawhttp.RawHTTPResponseDetails) {
			rawhttp.ReleaseResponseDetails(resp)
		}(response)

		// Update progress
		progressbar.Increment()
		progressbar.UpdateSpinnerText(
			"debugRequest",
			s.scannerOpts.Threads,
			worker.requestPool.GetReqWPActiveWorkers(),
			worker.requestPool.GetReqWPCompletedTasks(),
			worker.requestPool.GetReqWPSubmittedTasks(),
			worker.requestPool.GetRequestRate(),
			worker.requestPool.GetAverageRequestRate(),
		)

		// Only add to results if status code matches
		if matchStatusCodes(response.StatusCode, s.scannerOpts.MatchStatusCodes) {
			result := &Result{
				TargetURL:           displayURL, // Using displayURL for consistent logging
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

			// Write to file immediately like in RunBypassModule
			if err := AppendResultsToJsonL(GetResultsFile(), []*Result{result}); err != nil {
				GB403Logger.Error().Msgf("Failed to write result: %v\n", err)
			}

			results = append(results, result)
		}
	}

	// Final progress update
	progressbar.SpinnerSuccess(
		"debugRequest",
		s.scannerOpts.Threads,
		worker.requestPool.GetReqWPActiveWorkers(),
		worker.requestPool.GetReqWPCompletedTasks(),
		worker.requestPool.GetReqWPSubmittedTasks(),
		worker.requestPool.GetRequestRate(),
		worker.requestPool.GetAverageRequestRate(),
		worker.requestPool.GetPeakRequestRate(),
	)

	return results, nil
}

// match HTTP status code in list
// if codes is nil, match all status codes
func matchStatusCodes(code int, codes []int) bool {
	// If codes is nil, match all status codes
	if codes == nil {
		return true
	}

	// Otherwise match specific codes
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}
