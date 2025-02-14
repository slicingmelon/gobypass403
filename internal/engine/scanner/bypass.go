package scanner

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
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
	"dumb_check":          NewBypassModule("dumb_check"),
	"mid_paths":           NewBypassModule("mid_paths"),
	"end_paths":           NewBypassModule("end_paths"),
	"http_headers_ip":     NewBypassModule("http_headers_ip"),
	"case_substitution":   NewBypassModule("case_substitution"),
	"char_encode":         NewBypassModule("char_encode"),
	"http_host":           NewBypassModule("http_host"),
	"http_headers_scheme": NewBypassModule("http_headers_scheme"),
	"http_headers_port":   NewBypassModule("http_headers_port"),
	"http_headers_url":    NewBypassModule("http_headers_url"),
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
}

func NewBypassWorker(bypassmodule string, targetURL string, scannerOpts *ScannerOpts) *BypassWorker {
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

		requestPool: rawhttp.NewRequestWorkerPool(httpClientOpts, scannerOpts.Threads),
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

	// Validate URL one more time, who knows
	if _, err := rawurlparser.RawURLParse(targetURL); err != nil {
		err = GB403ErrorHandler.GetErrorHandler().HandleError(err, GB403ErrorHandler.ErrorContext{
			TargetURL:   []byte(targetURL),
			ErrorSource: []byte("Scanner.RunAllBypasses"),
		})
		if err != nil {
			GB403Logger.Error().Msgf("Failed to parse URL: %s\n", targetURL)
			close(results)
			return results
		}
	}

	go func() {
		defer close(results)

		// Run dumb check once at the start
		s.RunBypassModule("dumb_check", targetURL, results)

		bpModules := strings.Split(s.scannerOpts.BypassModule, ",")
		for _, module := range bpModules {
			module = strings.TrimSpace(module)

			if module == "all" {
				// Run all registered modules except dumb_check
				for bpModuleName := range bypassModules {
					if bpModuleName != "dumb_check" {
						s.RunBypassModule(bpModuleName, targetURL, results)
					}
				}
				continue
			}

			// Check if module exists in registry
			if _, exists := bypassModules[module]; exists && module != "dumb_check" {
				s.RunBypassModule(module, targetURL, results)
			} else {
				GB403Logger.Error().Msgf("Unknown bypass module: %s\n", module)
			}

		}
	}()

	return results
}

// Run a specific Bypass Module
func (s *Scanner) RunBypassModule(bypassModule string, targetURL string, results chan<- *Result) {
	moduleInstance, exists := bypassModules[bypassModule]
	if !exists {
		return
	}

	// Generate jobs
	allJobs := moduleInstance.GenerateJobs(targetURL, bypassModule, s.scannerOpts)
	if len(allJobs) == 0 {
		GB403Logger.Warning().Msgf("No jobs generated for bypass module: %s\n", bypassModule)
		return
	}

	worker := NewBypassWorker(bypassModule, targetURL, s.scannerOpts)
	defer worker.Stop()

	// Create progress bar
	progressbar := NewProgressBar(bypassModule, len(allJobs), s.scannerOpts.Threads)
	defer progressbar.Stop()

	progressbar.Start()

	// Process requests and update progress
	responses := worker.requestPool.ProcessRequests(allJobs)

	for response := range responses {
		if response == nil {
			continue
		}

		progressbar.Increment()
		progressbar.UpdateSpinnerText(
			bypassModule,
			s.scannerOpts.Threads,
			worker.requestPool.GetReqWPActiveWorkers(),
			worker.requestPool.GetReqWPCompletedTasks(),
			worker.requestPool.GetReqWPSubmittedTasks(),
			worker.requestPool.GetRequestRate(),
			worker.requestPool.GetAverageRequestRate(),
		)

		if matchStatusCodes(response.StatusCode, s.scannerOpts.MatchStatusCodes) {
			results <- &Result{
				TargetURL:       string(response.URL),
				BypassModule:    bypassModule,
				StatusCode:      response.StatusCode,
				ResponseHeaders: string(response.ResponseHeaders),
				CurlPocCommand:  string(response.CurlCommand),
				ResponsePreview: string(response.ResponsePreview),
				ContentType:     string(response.ContentType),
				ContentLength:   response.ContentLength,
				ResponseBytes:   response.ResponseBytes,
				Title:           string(response.Title),
				ServerInfo:      string(response.ServerInfo),
				RedirectURL:     string(response.RedirectURL),
				ResponseTime:    response.ResponseTime,
				DebugToken:      string(response.DebugToken),
			}
		}

		// release responsedetails buff
		rawhttp.ReleaseResponseDetails(response)
	}

	// Final progress update
	progressbar.SpinnerSuccess(
		bypassModule,
		s.scannerOpts.Threads,
		worker.requestPool.GetReqWPActiveWorkers(),
		worker.requestPool.GetReqWPCompletedTasks(),
		worker.requestPool.GetReqWPSubmittedTasks(),
		worker.requestPool.GetRequestRate(),
		worker.requestPool.GetAverageRequestRate(),
		worker.requestPool.GetPeakRequestRate(),
	)
}

func (s *Scanner) ScanDebugToken(debugToken string, resendCount int) ([]*Result, error) {
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
		BypassModule: "resend_request",
		PayloadToken: payload.GenerateDebugToken(payload.SeedData{FullURL: tokenData.FullURL}),
	}

	// Create worker
	worker := NewBypassWorker("resend_request", tokenData.FullURL, s.scannerOpts)
	defer worker.Stop()

	// Create jobs array
	jobs := make([]payload.PayloadJob, resendCount)
	for i := 0; i < resendCount; i++ {
		jobs[i] = job
		jobs[i].PayloadToken = payload.GenerateDebugToken(payload.SeedData{FullURL: tokenData.FullURL})
	}

	// Process all requests
	var results []*Result
	responses := worker.requestPool.ProcessRequests(jobs)

	for response := range responses {
		if response == nil {
			continue
		}

		result := &Result{
			TargetURL:       string(response.URL),
			BypassModule:    "resend_request",
			StatusCode:      response.StatusCode,
			ResponseHeaders: string(response.ResponseHeaders),
			CurlPocCommand:  string(response.CurlCommand),
			ResponsePreview: string(response.ResponsePreview),
			ContentType:     string(response.ContentType),
			ContentLength:   response.ContentLength,
			ResponseBytes:   response.ResponseBytes,
			Title:           string(response.Title),
			ServerInfo:      string(response.ServerInfo),
			RedirectURL:     string(response.RedirectURL),
			ResponseTime:    response.ResponseTime,
			DebugToken:      string(response.DebugToken),
		}

		results = append(results, result)
		rawhttp.ReleaseResponseDetails(response)
	}

	return results, nil
}

// func (s *Scanner) ResendRequestDirectly(job payload.PayloadJob, results chan<- *Result) {
// 	GB403Logger.Debug().Msgf("Creating bypass worker for module: %s", job.BypassModule)
// 	GB403Logger.Debug().Msgf("URL: %s", job.FullURL)
// 	GB403Logger.Debug().Msgf("Headers: %+v", job.Headers)

// 	// Create a bypass worker
// 	worker := NewBypassWorker(job.BypassModule, job.FullURL, s.scannerOpts, s.errorHandler)
// 	defer worker.Stop()

// 	GB403Logger.Debug().Msgf("Processing request through worker pool...")

// 	// Process the request
// 	responses := worker.requestPool.ProcessRequests([]payload.PayloadJob{job})

// 	responseReceived := false
// 	GB403Logger.Debug().Msgf("Processing responses...")

// 	for response := range responses {
// 		responseReceived = true
// 		if response == nil {
// 			GB403Logger.Debug().Msgf("Received nil response")
// 			continue
// 		}

// 		GB403Logger.Debug().Msgf("Received response with status code: %d", response.StatusCode)
// 		GB403Logger.Debug().Msgf("Response headers: %s", string(response.ResponseHeaders))
// 		GB403Logger.Debug().Msgf("Response preview: %s", string(response.ResponsePreview))

// 		// Always create and send the result for resend requests
// 		result := &Result{
// 			TargetURL:       string(response.URL),
// 			BypassModule:    job.BypassModule,
// 			StatusCode:      response.StatusCode,
// 			ResponseHeaders: string(response.ResponseHeaders),
// 			CurlPocCommand:  string(response.CurlCommand),
// 			ResponsePreview: string(response.ResponsePreview),
// 			ContentType:     string(response.ContentType),
// 			ContentLength:   response.ContentLength,
// 			ResponseBytes:   response.ResponseBytes,
// 			Title:           string(response.Title),
// 			ServerInfo:      string(response.ServerInfo),
// 			RedirectURL:     string(response.RedirectURL),
// 			ResponseTime:    response.ResponseTime,
// 			DebugToken:      string(response.DebugToken),
// 		}

// 		GB403Logger.Debug().Msgf("Sending result to channel...")
// 		results <- result
// 		GB403Logger.Debug().Msgf("Result sent to channel")

// 		// Release response details
// 		rawhttp.ReleaseResponseDetails(response)
// 	}

// 	if !responseReceived {
// 		GB403Logger.Warning().Msgf("No response was received from the request pool")
// 	}

// 	GB403Logger.Debug().Msgf("Finished processing request")
// }

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
