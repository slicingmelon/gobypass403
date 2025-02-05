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
	progress     *ProgressCounter
	cancel       chan struct{}
	wg           *sync.WaitGroup
	once         sync.Once
	opts         *ScannerOpts
	requestPool  *rawhttp.RequestWorkerPool
	workerCount  int32
}

func NewBypassWorker(bypassmodule string, total int, targetURL string, scannerOpts *ScannerOpts, errorHandler *GB403ErrorHandler.ErrorHandler, progress *ProgressCounter) *BypassWorker {
	httpClientOpts := rawhttp.DefaultHTTPClientOptions()

	// Override specific settings from user options
	httpClientOpts.Timeout = time.Duration(scannerOpts.Timeout) * time.Second
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

	return &BypassWorker{
		bypassmodule: bypassmodule,
		progress:     progress,
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
			GB403Logger.Error().Msgf("Failed to parse URL: %s", targetURL)
			close(results)
			return results
		}
	}

	go func() {
		defer close(results)

		// Run dumb check once at the start
		s.RunBypassModule("dumb_check", targetURL, results)

		modes := strings.Split(s.config.BypassModule, ",")
		for _, mode := range modes {
			mode = strings.TrimSpace(mode)

			if mode == "all" {
				// Run all registered modules except dumb_check
				for modeName := range bypassModules {
					if modeName != "dumb_check" {
						s.RunBypassModule(modeName, targetURL, results)
					}
				}

				continue
			}

			// Check if module exists in registry
			if _, exists := bypassModules[mode]; exists && mode != "dumb_check" {
				s.RunBypassModule(mode, targetURL, results)
			} else {
				GB403Logger.Error().Msgf("Unknown bypass mode: %s", mode)
			}

		}
	}()

	return results
}

// Run a specific bypass module
func (s *Scanner) RunBypassModule(bypassModule string, targetURL string, results chan<- *Result) {
	moduleInstance, exists := bypassModules[bypassModule]
	if !exists {
		return
	}

	allJobs := moduleInstance.GenerateJobs(targetURL, bypassModule, s.config)
	if len(allJobs) == 0 {
		GB403Logger.Verbose().Msgf("No jobs generated for module: %s", bypassModule)
		return
	}

	s.progress.StartModule(bypassModule, len(allJobs), targetURL)
	lastStatsUpdate := time.Now()

	ctx := NewBypassWorker(bypassModule, len(allJobs), targetURL, s.config, s.errorHandler, s.progress)
	defer func() {
		// Get stats from pond pool
		// running, submitted, waiting, completed
		running := ctx.requestPool.GetReqWPActiveWorkers()
		s.progress.UpdateWorkerStats(bypassModule, running)
		ctx.Stop()
		time.Sleep(100 * time.Millisecond)
		s.progress.MarkModuleAsDone(bypassModule)

	}()

	responses := ctx.requestPool.ProcessRequests(allJobs)
	for response := range responses {
		if response == nil {
			s.progress.IncrementProgress(bypassModule, false)
			continue
		}
		s.progress.IncrementProgress(bypassModule, true)

		if time.Since(lastStatsUpdate) > 500*time.Millisecond {
			// Get stats from pond pool
			// running, submitted, waiting, completed
			running := ctx.requestPool.GetReqWPActiveWorkers()
			s.progress.UpdateWorkerStats(bypassModule, running)
			lastStatsUpdate = time.Now()

		}

		if matchStatusCodes(response.StatusCode, s.config.MatchStatusCodes) {
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
			}
		}
	}
	if ctx.requestPool != nil {
		ctx.requestPool.Close()
	}
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
