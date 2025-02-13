package scanner

import (
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

func NewBypassWorker(bypassmodule string, targetURL string, scannerOpts *ScannerOpts, errorHandler *GB403ErrorHandler.ErrorHandler) *BypassWorker {
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
	if scannerOpts.Delay > 0 {
		httpClientOpts.RequestDelay = time.Duration(scannerOpts.Delay) * time.Millisecond
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

		requestPool: rawhttp.NewRequestWorkerPool(httpClientOpts, scannerOpts.Threads, errorHandler),
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
		err = s.errorHandler.HandleError(err, GB403ErrorHandler.ErrorContext{
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

	worker := NewBypassWorker(bypassModule, targetURL, s.scannerOpts, s.errorHandler)
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

// func (s *Scanner) ResendRequestWithDebugToken(debugToken string, results chan<- *Result) {
// 	if debugToken == "" {
// 		GB403Logger.Error().Msgf("Debug token is empty\n")
// 		return
// 	}

// 	tokenData, err := payload.DecodeDebugToken(debugToken)
// 	if err != nil {
// 		GB403Logger.Error().Msgf("Failed to decode debug token: %s\n", err)
// 		return
// 	}

// 	// Create a single job for the resend request
// 	job := payload.PayloadJob{
// 		FullURL: tokenData.FullURL,
// 		Headers: tokenData.Headers,
// 	}

// 	// Create a bypass worker
// 	worker := NewBypassWorker(tokenData.BypassModule, tokenData.FullURL, s.scannerOpts, s.errorHandler)
// 	defer worker.Stop()

// 	// Process the request
// 	responses := worker.requestPool.ProcessRequests([]payload.PayloadJob{job})

// 	for response := range responses {
// 		if response == nil {
// 			continue
// 		}

// 		// Create a result object
// 		result := &Result{
// 			TargetURL:       string(response.URL),
// 			BypassModule:    tokenData.BypassModule,
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

// 		// Send the result to the channel
// 		results <- result

// 		// Release response details
// 		rawhttp.ReleaseResponseDetails(response)
// 	}
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
