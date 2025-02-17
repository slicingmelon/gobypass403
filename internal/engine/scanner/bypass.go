package scanner

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/slicingmelon/go-rawurlparser"
)

// BypassModule defines the interface for all bypass modules
type BypassModule struct {
	Name         string
	payloadGen   *payload.PayloadGenerator
	GenerateJobs func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob
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
			module.GenerateJobs = func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob {
				return module.payloadGen.GenerateDumbJob(targetURL, mode)
			}
		case "mid_paths":
			module.GenerateJobs = func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob {
				return module.payloadGen.GenerateMidPathsJobs(targetURL, mode)
			}
		case "end_paths":
			module.GenerateJobs = func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob {
				return module.payloadGen.GenerateEndPathsJobs(targetURL, mode)
			}
		case "http_headers_ip":
			module.GenerateJobs = func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob {
				return module.payloadGen.GenerateHeaderIPJobs(targetURL, mode, opts.SpoofHeader, opts.SpoofIP)
			}
		case "case_substitution":
			module.GenerateJobs = func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob {
				return module.payloadGen.GenerateCaseSubstitutionJobs(targetURL, mode)
			}
		case "char_encode":
			module.GenerateJobs = func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob {
				return module.payloadGen.GenerateCharEncodeJobs(targetURL, mode)
			}
		case "http_host":
			module.GenerateJobs = func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob {
				return module.payloadGen.GenerateHostHeaderJobs(targetURL, mode, opts.ReconCache)
			}
		case "http_headers_scheme":
			module.GenerateJobs = func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob {
				return module.payloadGen.GenerateHeaderSchemeJobs(targetURL, mode)
			}
		case "http_headers_port":
			module.GenerateJobs = func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob {
				return module.payloadGen.GenerateHeaderPortJobs(targetURL, mode)
			}
		case "http_headers_url":
			module.GenerateJobs = func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob {
				return module.payloadGen.GenerateHeaderURLJobs(targetURL, mode)
			}
		case "unicode_path_normalization":
			module.GenerateJobs = func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob {
				return module.payloadGen.GenerateUnicodePathNormalizationsJobs(targetURL, mode)
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

	// Ensure MaxConnsPerHost is at least equal to number of workers plus buffer
	if scannerOpts.Threads > httpClientOpts.MaxConnsPerHost {
		// Add 50% more connections than workers for buffer
		httpClientOpts.MaxConnsPerHost = scannerOpts.Threads + (scannerOpts.Threads / 2)
	}

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

	// Initialize progress bar with initial state
	progressBar := NewProgressBar(bypassModule, len(allJobs), s.scannerOpts.Threads)
	progressBar.Start()
	defer progressBar.Stop()

	responses := worker.requestPool.ProcessRequests(allJobs)

	outputFile := filepath.Join(s.scannerOpts.OutDir, "findings.json")

	// Process responses and update progress based on pool metrics
	for response := range responses {
		if response == nil {
			continue
		}

		// Update progress bar to match pool state
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

		if matchStatusCodes(response.StatusCode, s.scannerOpts.MatchStatusCodes) {
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
			if err := AppendResultsToJsonL(outputFile, []*Result{result}); err != nil {
				GB403Logger.Error().Msgf("Failed to write result: %v\n", err)
			}

			// Send to channel for progress tracking
			results <- result
		}

		rawhttp.ReleaseResponseDetails(response)
	}

	// Final success state
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

func (s *Scanner) ResendRequestWithToken(debugToken string, resendCount int) ([]*Result, error) {

	// Parse URL from token
	tokenData, err := payload.DecodeDebugToken(debugToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode debug token: %w", err)
	}

	parsedURL, err := rawurlparser.RawURLParse(tokenData.FullURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL from token: %w", err)
	}

	// Create base job
	job := payload.PayloadJob{
		FullURL:      tokenData.FullURL,
		Method:       "GET",
		Host:         parsedURL.Host,
		Scheme:       parsedURL.Scheme,
		RawURI:       parsedURL.Path,
		Headers:      tokenData.Headers,
		BypassModule: "debugRequest",
		PayloadToken: payload.GenerateDebugToken(payload.SeedData{FullURL: tokenData.FullURL}),
	}

	// Create worker
	worker := NewBypassWorker("debugRequest", tokenData.FullURL, s.scannerOpts, resendCount)
	defer worker.Stop()

	// Create jobs array
	jobs := make([]payload.PayloadJob, resendCount)
	for i := 0; i < resendCount; i++ {
		jobs[i] = job
		jobs[i].PayloadToken = payload.GenerateDebugToken(payload.SeedData{FullURL: tokenData.FullURL})
	}

	// Create progress bar
	progressbar := NewProgressBar("debugRequest", len(jobs), s.scannerOpts.Threads)
	defer progressbar.Stop()
	progressbar.Start()

	// Process all requests
	var results []*Result
	responses := worker.requestPool.ProcessRequests(jobs)

	for response := range responses {
		if response == nil {
			continue
		}

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

			results = append(results, result)
		}

		rawhttp.ReleaseResponseDetails(response)
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
