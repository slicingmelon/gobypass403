package scanner

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/utils/errkit"
	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/utils/error"
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
	// Add dumb_check to registry
	"dumb_check": {
		Name:         "dumb_check",
		GenerateJobs: payload.GenerateDumbJob,
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
		Name:         "http_headers_ip",
		GenerateJobs: func(targetURL string, opts *ScannerOpts) []payload.PayloadJob {
            return payload.GenerateHeaderIPJobs(targetURL, opts.SpoofHeader, opts.SpoofIP)
        },
	},
	"case_substitution": {
		Name:         "case_substitution",
		GenerateJobs: payload.GenerateCaseSubstitutionJobs,
	},
	"char_encode": {
		Name:         "char_encode",
		GenerateJobs: payload.GenerateCharEncodeJobs,
	},
}

type WorkerContext struct {
	mode     string
	progress *ProgressCounter
	cancel   chan struct{}
	wg       *sync.WaitGroup
	once     sync.Once
}

func NewWorkerContext(mode string, total int) *WorkerContext {
	return &WorkerContext{
		mode: mode,
		progress: &ProgressCounter{
			Total: total,
			Mode:  mode,
		},
		cancel: make(chan struct{}),
		wg:     &sync.WaitGroup{},
		once:   sync.Once{},
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

		modes := strings.Split(s.config.BypassModule, ",")
		for _, mode := range modes {
			mode = strings.TrimSpace(mode)

			// Always run dumb check first for each mode
			runDumbCheck(targetURL, results)

			if mode == "all" {
				// Run all registered modules
				for modeName := range bypassModules {
					runBypassForMode(modeName, targetURL, results)
				}
				continue
			}

			// Check if module exists in registry
			if _, exists := bypassModules[mode]; exists {
				runBypassForMode(mode, targetURL, results)
			} else {
				logger.LogError("Unknown bypass mode: %s", mode)
			}
		}
	}()

	return results
}

// runDumbCheck runs the baseline check using the same worker pattern
func runDumbCheck(targetURL string, results chan<- *Result) {
    jobs := make(chan payload.PayloadJob, 1000)
    allJobs := payload.GenerateDumbJob(targetURL)

    ctx := NewWorkerContext("dumb_check", len(allJobs))

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
    

// Generic runner that replaces all individual run*Bypass functions
func (s *Scanner) runBypassForMode(module string, targetURL string, results chan<- *Result) {
    module, exists := bypassModules[module]
    if !exists {
        return
    }

    jobs := make(chan payload.PayloadJob, 1000)
    allJobs := module.GenerateJobs(targetURL, mode, s.config)

	ctx := NewWorkerContext(mode, len(allJobs))

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

	// Add panic recovery
	defer func() {
		if r := recover(); r != nil {
			logger.LogError("[%s] Worker panic recovered: %v", ctx.mode, r)
			ctx.Stop()
		}
	}()

	// Create client
	client, err := New(&config, ctx.mode)
	if err != nil {
		logger.LogError("Failed to create client for mode %s: %v", ctx.mode, err)
		return
	}
	defer func() {
		// Print all URL parsing logs before closing the client
		client.PrintAllLogs()
		client.Close()
	}()

	workerLimiter := time.NewTicker(time.Duration(config.Delay) * time.Millisecond)
	defer workerLimiter.Stop()

	for job := range jobs {
		select {
		case <-ctx.cancel:
			return
		case <-workerLimiter.C:
			details, err := client.sendRequest(job.method, job.url, job.headers)
			ctx.progress.increment()

			if err != nil {
				_, parseErr := rawurlparser.RawURLParse(job.url)
				if parseErr != nil {
					logger.LogError("[%s] Failed to parse URL: %s", job.bypassMode, job.url)
					continue
				}

				if errkit.IsKind(err, error.ErrKindGo403BypassFatal) {
					logger.LogError("[ErrorMonitorService] => Stopping current bypass mode [%s] -- Permanent error for %s: %v",
						job.bypassMode, job.url, err)
					ctx.Stop()
					return
				}

				logger.LogError("[%s] Request error for %s: %v",
					job.bypassMode, job.url, err)
				continue
			}

			// Process successful response
			for _, allowedCode := range config.MatchStatusCodes {
				if details.StatusCode == allowedCode {
					results <- &Result{
						TargetURL:       job.url,
						StatusCode:      details.StatusCode,
						ResponsePreview: details.ResponsePreview,
						ResponseHeaders: details.ResponseHeaders,
						CurlPocCommand:  BuildCurlCmd(job.method, job.url, payload.HeadersToMap(job.headers)),
						BypassModule:    job.bypassMode,
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
