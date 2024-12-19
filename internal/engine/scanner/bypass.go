package scanner

import (
	"strings"
	"sync"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp"
	GB403ErrHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/slicingmelon/go-rawurlparser"
)

// BypassModule defines the interface for all bypass modules
type BypassModule struct {
	Name         string
	GenerateJobs func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob
}

// Registry of all bypass modules
var bypassModules = map[string]*BypassModule{
	"dumb_check": {
		Name: "dumb_check",
		GenerateJobs: func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob {
			return payload.GenerateDumbJob(targetURL, mode)
		},
	},
	"mid_paths": {
		Name: "mid_paths",
		GenerateJobs: func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob {
			return payload.GenerateMidPathsJobs(targetURL, mode)
		},
	},
	"end_paths": {
		Name: "end_paths",
		GenerateJobs: func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob {
			return payload.GenerateEndPathsJobs(targetURL, mode)
		},
	},
	"http_headers_ip": {
		Name: "http_headers_ip",
		GenerateJobs: func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob {
			return payload.GenerateHeaderIPJobs(targetURL, mode, opts.SpoofHeader, opts.SpoofIP)
		},
	},
	"case_substitution": {
		Name: "case_substitution",
		GenerateJobs: func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob {
			return payload.GenerateCaseSubstitutionJobs(targetURL, mode)
		},
	},
	"char_encode": {
		Name: "char_encode",
		GenerateJobs: func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob {
			return payload.GenerateCharEncodeJobs(targetURL, mode)
		},
	},
	"http_host": {
		Name: "http_host",
		GenerateJobs: func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob {
			return payload.GenerateHostHeaderJobs(targetURL, mode, opts.ProbeCache)
		},
	},
	"http_headers_scheme": {
		Name: "http_headers_scheme",
		GenerateJobs: func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob {
			return payload.GenerateHeaderSchemeJobs(targetURL, mode)
		},
	},
	"http_headers_port": {
		Name: "http_headers_port",
		GenerateJobs: func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob {
			return payload.GenerateHeaderPortJobs(targetURL, mode)
		},
	},
	"http_headers_url": {
		Name: "http_headers_url",
		GenerateJobs: func(targetURL string, mode string, opts *ScannerOpts) []payload.PayloadJob {
			return payload.GenerateHeaderURLJobs(targetURL, mode)
		},
	},
}

type WorkerContext struct {
	mode        string
	progress    *ProgressCounter
	cancel      chan struct{}
	wg          *sync.WaitGroup
	once        sync.Once
	opts        *ScannerOpts
	logger      *GB403Logger.Logger
	requestPool *rawhttp.RequestPool
	workerCount int32
}

func NewWorkerContext(mode string, total int, targetURL string, opts *ScannerOpts, errHandler *GB403ErrHandler.ErrorHandler, progress *ProgressCounter) *WorkerContext {
	clientOpts := rawhttp.DefaultOptionsSameHost()

	// Override specific settings from user options
	clientOpts.Timeout = time.Duration(opts.Timeout) * time.Second
	clientOpts.MaxConnsPerHost = opts.Threads
	clientOpts.ProxyURL = opts.Proxy
	clientOpts.ReadBufferSize = opts.ResponseBodyPreviewSize

	return &WorkerContext{
		mode:     mode,
		progress: progress,
		cancel:   make(chan struct{}),
		wg:       &sync.WaitGroup{},
		once:     sync.Once{},
		opts:     opts,
		logger:   logger,
		requestPool: rawhttp.NewRequestPool(clientOpts, &rawhttp.ScannerCliOpts{
			MatchStatusCodes:        opts.MatchStatusCodes,
			ResponseBodyPreviewSize: opts.ResponseBodyPreviewSize,
			ModuleName:              mode,
		}, errHandler, logger),
	}
}

func (w *WorkerContext) Stop() {
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
		err = s.errHandler.HandleError(err, GB403ErrHandler.ErrorContext{
			TargetURL:   []byte(targetURL),
			ErrorSource: []byte("Scanner.RunAllBypasses"),
		})
		if err != nil {
			s.logger.LogError("Failed to parse URL: %s", targetURL)
			close(results)
			return results
		}
	}

	go func() {
		defer close(results)

		// Run dumb check once at the start
		s.runBypassForMode("dumb_check", targetURL, results)

		modes := strings.Split(s.config.BypassModule, ",")
		for _, mode := range modes {
			mode = strings.TrimSpace(mode)

			if mode == "all" {
				// Run all registered modules except dumb_check
				for modeName := range bypassModules {
					if modeName != "dumb_check" {
						s.runBypassForMode(modeName, targetURL, results)
					}
				}
				continue
			}

			// Check if module exists in registry
			if _, exists := bypassModules[mode]; exists && mode != "dumb_check" {
				s.runBypassForMode(mode, targetURL, results)
			} else {
				s.logger.LogError("Unknown bypass mode: %s", mode)
			}
		}
	}()

	return results
}

// Generic runner that replaces all individual run*Bypass functions
func (s *Scanner) runBypassForMode(bypassModule string, targetURL string, results chan<- *Result) {
	moduleInstance, exists := bypassModules[bypassModule]
	if !exists {
		return
	}

	allJobs := moduleInstance.GenerateJobs(targetURL, bypassModule, s.config)
	if len(allJobs) == 0 {
		s.logger.LogVerbose("No jobs generated for module: %s", bypassModule)
		return
	}

	s.progress.StartModule(bypassModule, len(allJobs), targetURL)
	lastStatsUpdate := time.Now()

	ctx := NewWorkerContext(bypassModule, len(allJobs), targetURL, s.config, s.errHandler, s.progress)
	defer func() {
		// Let the request pool finish and get final worker count
		finalWorkerCount := ctx.requestPool.ActiveWorkers()
		s.progress.UpdateWorkerStats(bypassModule, int64(finalWorkerCount))
		ctx.Stop()
		// Small delay to allow progress display to update
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
			s.progress.UpdateWorkerStats(bypassModule, int64(ctx.requestPool.ActiveWorkers()))
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
func matchStatusCodes(code int, codes []int) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}
