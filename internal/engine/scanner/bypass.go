package scanner

import (
	"fmt"
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
	// Create request pool with options
	poolOpts := &rawhttp.ClientOptions{
		Timeout:             time.Duration(opts.Timeout) * time.Second,
		MaxConnsPerHost:     opts.Threads,
		MaxIdleConnDuration: 30 * time.Second,
		NoDefaultUserAgent:  true,
		ProxyURL:            opts.Proxy,
		ReadBufferSize:      opts.MaxResponseBodySize,
		DisableKeepAlive:    false,
	}

	return &WorkerContext{
		mode: mode,
		progress: &ProgressCounter{
			Total: total,
			Mode:  mode,
			URL:   targetURL,
		},
		cancel:      make(chan struct{}),
		wg:          &sync.WaitGroup{},
		once:        sync.Once{},
		opts:        opts,
		requestPool: rawhttp.NewRequestPool(poolOpts),
	}
}

func (w *WorkerContext) Stop() {
	w.once.Do(func() {
		close(w.cancel)
		w.progress.markAsCancelled()
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
		s.runDumbCheck(targetURL, results)

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

// runDumbCheck runs the baseline check using the same worker pattern
func (s *Scanner) runDumbCheck(targetURL string, results chan<- *Result) {
	jobs := make(chan payload.PayloadJob, 1000)
	allJobs := payload.GenerateDumbJob(targetURL, "dumb_check")

	ctx := NewWorkerContext("dumb_check", len(allJobs), targetURL, s.config)

	// Start workers
	for i := 0; i < 2; i++ {
		ctx.wg.Add(1)
		go worker(ctx, jobs, results)
	}

	// Process jobs
	for _, job := range allJobs {
		select {
		case <-ctx.cancel:
			close(jobs)
			ctx.wg.Wait()
			return
		case jobs <- job:
		}
	}

	close(jobs)
	ctx.wg.Wait()

}

// Generic runner that replaces all individual run*Bypass functions
func (s *Scanner) runBypassForMode(BypassModule string, targetURL string, results chan<- *Result) {
	moduleInstance, exists := bypassModules[BypassModule]
	if !exists {
		return
	}

	jobs := make(chan payload.PayloadJob, 1000)
	allJobs := moduleInstance.GenerateJobs(targetURL, BypassModule, s.config)

	ctx := NewWorkerContext(BypassModule, len(allJobs), targetURL, s.config)

	// Start workers
	for i := 0; i < s.config.Threads; i++ {
		ctx.wg.Add(1)
		go worker(ctx, jobs, results)
	}

	// Process jobs
	for _, job := range allJobs {
		select {
		case <-ctx.cancel:
			close(jobs)
			ctx.wg.Wait()
			return
		case jobs <- job:
		}
	}

	close(jobs)
	ctx.wg.Wait()
	fmt.Println()
}

func worker(ctx *WorkerContext, jobs <-chan payload.PayloadJob, results chan<- *Result) {
	defer ctx.wg.Done()

	// Use the rate limiter if delay is specified
	var limiter *time.Ticker
	if ctx.opts.Delay > 0 {
		limiter = time.NewTicker(time.Duration(ctx.opts.Delay) * time.Millisecond)
		defer limiter.Stop()
	}

	// Process jobs through the request pool
	for details := range ctx.requestPool.ProcessRequests(jobs) {
		select {
		case <-ctx.cancel:
			return
		default:
			// Rate limiting if enabled
			if limiter != nil {
				<-limiter.C
			}

			if details == nil {
				continue
			}

			ctx.progress.increment()

			// Check if status code matches
			for _, allowedCode := range ctx.opts.MatchStatusCodes {
				if details.StatusCode == allowedCode {
					results <- &Result{
						TargetURL:       details.URL,
						BypassModule:    details.BypassMode,
						CurlPocCommand:  details.CurlCommand,
						ResponseHeaders: details.ResponseHeaders,
						ResponsePreview: details.ResponsePreview,
						StatusCode:      details.StatusCode,
						ContentType:     details.ContentType,
						ContentLength:   details.ContentLength,
						ResponseBytes:   details.ResponseBytes,
						Title:           details.Title,
						ServerInfo:      details.ServerInfo,
						RedirectURL:     details.RedirectURL,
					}
				}
			}
		}
	}
}
