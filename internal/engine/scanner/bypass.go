package scanner

import (
	"strings"
	"sync"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp"
	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
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
	requestPool *rawhttp.RequestPool
}

func NewWorkerContext(mode string, total int, targetURL string, opts *ScannerOpts) *WorkerContext {
	// Start with default single host options since we're targeting one URL
	clientOpts := rawhttp.DefaultOptionsSameHost()

	// Override specific settings from user options
	clientOpts.Timeout = time.Duration(opts.Timeout) * time.Second
	clientOpts.MaxConnsPerHost = opts.Threads
	clientOpts.ProxyURL = opts.Proxy
	clientOpts.ReadBufferSize = opts.ResponseBodyPreviewSize

	return &WorkerContext{
		mode: mode,
		progress: &ProgressCounter{
			Total: total,
			Mode:  mode,
			URL:   targetURL,
		},
		cancel: make(chan struct{}),
		wg:     &sync.WaitGroup{},
		once:   sync.Once{},
		opts:   opts,
		requestPool: rawhttp.NewRequestPool(clientOpts, &rawhttp.ScannerCliOpts{
			MatchStatusCodes:        opts.MatchStatusCodes,
			ResponseBodyPreviewSize: opts.ResponseBodyPreviewSize,
		}),
	}
}

func (w *WorkerContext) Stop() {
	w.once.Do(func() {
		select {
		case <-w.cancel: // Already closed
			return
		default:
			close(w.cancel)
			w.progress.markAsCancelled()
		}
	})
}

// Core Function
func (s *Scanner) RunAllBypasses(targetURL string) chan *Result {
	results := make(chan *Result)

	// Validate URL
	if _, err := rawurlparser.RawURLParse(targetURL); err != nil {
		logger.LogError("Failed to parse URL: %s", targetURL)
		close(results)
		return results
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
				logger.LogError("Unknown bypass mode: %s", mode)
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
		logger.LogVerbose("No jobs generated for module: %s", bypassModule)
		return
	}

	ctx := NewWorkerContext(bypassModule, len(allJobs), targetURL, s.config)
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()

		responses := ctx.requestPool.ProcessRequests(allJobs)
		foundMatch := false

		for response := range responses {
			if response == nil {
				ctx.progress.increment()
				continue
			}

			ctx.progress.increment()

			// Check for matching status codes
			for _, code := range s.config.MatchStatusCodes {
				if response.StatusCode == code {
					foundMatch = true
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
		}

		// Only log if we completed all requests but found no matches
		if !foundMatch {
			logger.LogVerbose("\n[%s] No matching status codes found\n", bypassModule)
		}
	}()

	wg.Wait()
}
