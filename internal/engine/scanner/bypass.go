package scanner

import (
	"context"
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
	mode     string
	progress *ProgressCounter
	cancel   chan struct{}
	wg       *sync.WaitGroup
	once     sync.Once
}

func NewWorkerContext(mode string, total int, targetURL string) *WorkerContext {
	return &WorkerContext{
		mode: mode,
		progress: &ProgressCounter{
			Total: total,
			Mode:  mode,
			URL:   targetURL, // Pass URL here
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

	ctx := NewWorkerContext("dumb_check", len(allJobs), targetURL)

	// Start workers
	for i := 0; i < 2; i++ {
		ctx.wg.Add(1)
		go worker(ctx, jobs, results, s.config)
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

	ctx := NewWorkerContext(BypassModule, len(allJobs), targetURL)

	// Start workers
	for i := 0; i < s.config.Threads; i++ {
		ctx.wg.Add(1)
		go worker(ctx, jobs, results, s.config)
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

func worker(ctx *WorkerContext, jobs <-chan payload.PayloadJob, results chan<- *Result, opts *ScannerOpts) {
	defer ctx.wg.Done()

	// Add panic recovery
	defer func() {
		if r := recover(); r != nil {
			logger.LogError("[%s] Worker panic recovered: %v", ctx.mode, r)
			ctx.Stop()
		}
	}()

	// Create client with options
	clientOpts := &rawhttp.ClientOptions{
		Timeout:             time.Duration(opts.Timeout) * time.Second,
		MaxConnsPerHost:     512,
		MaxIdleConnDuration: 10 * time.Second,
		NoDefaultUserAgent:  true,
		ProxyURL:            opts.Proxy,
		MaxResponseBodySize: opts.MaxResponseBodySize,
	}

	client := rawhttp.NewHTTPClient(clientOpts)
	defer client.Close()

	workerLimiter := time.NewTicker(time.Duration(opts.Delay) * time.Millisecond)
	defer workerLimiter.Stop()

	for job := range jobs {
		select {
		case <-ctx.cancel:
			return
		case <-workerLimiter.C:
			// Create request with context
			reqCtx := context.Background()
			req := rawhttp.NewRequestWithContext(reqCtx, job.Method, job.URL, payload.HeadersToMap(job.Headers))

			// Send request
			resp, err := client.SendRequest(req)
			ctx.progress.increment()

			if err != nil {
				logger.LogError("[%s] Request error for %s: %v",
					job.BypassMode, job.URL, err)
				req.Release()
				continue
			}

			// Extract response details
			details := &ResponseDetails{
				StatusCode:      resp.StatusCode(),
				ResponsePreview: string(resp.Body()),
				ResponseHeaders: resp.Header.String(),
				ContentType:     string(resp.Header.ContentType()),
				ContentLength:   int64(resp.Header.ContentLength()),
				ResponseBytes:   len(resp.Body()),
				//Title:           extractTitle(resp.Body()), // You'll need to implement this
				ServerInfo: string(resp.Header.Peek("Server")),
			}

			// Process successful response
			for _, allowedCode := range opts.MatchStatusCodes {
				if details.StatusCode == allowedCode {
					results <- &Result{
						TargetURL:       job.URL,
						StatusCode:      details.StatusCode,
						ResponsePreview: details.ResponsePreview,
						ResponseHeaders: details.ResponseHeaders,
						CurlPocCommand:  BuildCurlCmd(job.Method, job.URL, payload.HeadersToMap(job.Headers)),
						BypassModule:    job.BypassMode,
						ContentType:     details.ContentType,
						ContentLength:   details.ContentLength,
						ResponseBytes:   details.ResponseBytes,
						Title:           details.Title,
						ServerInfo:      details.ServerInfo,
						RedirectURL:     string(resp.Header.Peek("Location")),
					}
				}
			}

			// Clean up
			req.Release()
			client.ReleaseResponse(resp)
		}
	}
}

// func worker(ctx *WorkerContext, jobs <-chan payload.PayloadJob, results chan<- *Result, opts *ScannerOpts) {
// 	defer ctx.wg.Done()

// 	// Add panic recovery
// 	defer func() {
// 		if r := recover(); r != nil {
// 			logger.LogError("[%s] Worker panic recovered: %v", ctx.mode, r)
// 			ctx.Stop()
// 		}
// 	}()

// 	// Comment out client creation for now
// 	/*
// 	   client, err := NewClient(opts, ctx.mode)
// 	   if err != nil {
// 	       logger.LogError("Failed to create client for mode %s: %v", ctx.mode, err)
// 	       return
// 	   }
// 	   defer func() {
// 	       client.PrintAllLogs()
// 	       client.Close()
// 	   }()
// 	*/

// 	workerLimiter := time.NewTicker(time.Duration(opts.Delay) * time.Millisecond)
// 	defer workerLimiter.Stop()

// 	for job := range jobs {
// 		select {
// 		case <-ctx.cancel:
// 			return
// 		case <-workerLimiter.C:
// 			// Mock response for testing
// 			details := &ResponseDetails{
// 				StatusCode:      200,
// 				ResponsePreview: "Test Response",
// 				ResponseHeaders: "Test Headers",
// 				ContentType:     "text/html",
// 				ContentLength:   100,
// 				ResponseBytes:   100,
// 				Title:           "Test Title",
// 				ServerInfo:      "Test Server",
// 			}

// 			ctx.progress.increment()

// 			// Process successful response
// 			for _, allowedCode := range opts.MatchStatusCodes {
// 				if details.StatusCode == allowedCode {
// 					results <- &Result{
// 						TargetURL:       job.URL,
// 						StatusCode:      details.StatusCode,
// 						ResponsePreview: details.ResponsePreview,
// 						ResponseHeaders: details.ResponseHeaders,
// 						CurlPocCommand:  BuildCurlCmd(job.Method, job.URL, payload.HeadersToMap(job.Headers)),
// 						BypassModule:    job.BypassMode,
// 						ContentType:     details.ContentType,
// 						ContentLength:   details.ContentLength,
// 						ResponseBytes:   details.ResponseBytes,
// 						Title:           details.Title,
// 						ServerInfo:      details.ServerInfo,
// 						RedirectURL:     details.RedirectURL,
// 					}
// 				}
// 			}
// 		}
// 	}
// }

// func worker(ctx *WorkerContext, jobs <-chan payload.PayloadJob, results chan<- *Result, opts *ScannerOpts) {
// 	defer ctx.wg.Done()

// 	// Add panic recovery
// 	defer func() {
// 		if r := recover(); r != nil {
// 			logger.LogError("[%s] Worker panic recovered: %v", ctx.mode, r)
// 			ctx.Stop()
// 		}
// 	}()

// 	// Create client
// 	//nolint:errcheck
// 	client, err := NewClient(opts, ctx.mode) //nolint:errcheck
// 	if err != nil {
// 		logger.LogError("WEEEE REACHED THE END!!! Failed to create client for mode %s: %v", ctx.mode, err)
// 		return
// 	}
// 	defer func() {
// 		// Print all URL parsing logs before closing the client
// 		client.PrintAllLogs()
// 		client.Close()
// 	}()

// 	workerLimiter := time.NewTicker(time.Duration(opts.Delay) * time.Millisecond)
// 	defer workerLimiter.Stop()

// 	for job := range jobs {
// 		select {
// 		case <-ctx.cancel:
// 			return
// 		case <-workerLimiter.C:
// 			details, err := client.sendRequest(job.Method, job.URL, job.Headers)
// 			ctx.progress.increment()

// 			if err != nil {
// 				if errkit.IsKind(err, error.ErrKindGo403BypassFatal) {
// 					logger.LogError("[ErrorMonitorService] => Stopping current bypass mode [%s] -- Permanent error for %s: %v",
// 						job.BypassMode, job.URL, err)
// 					ctx.Stop()
// 					return
// 				}

// 				logger.LogError("[%s] Request error for %s: %v",
// 					job.BypassMode, job.URL, err)
// 				continue
// 			}

// 			// Process successful response
// 			for _, allowedCode := range opts.MatchStatusCodes {
// 				if details.StatusCode == allowedCode {
// 					results <- &Result{
// 						TargetURL:       job.URL,
// 						StatusCode:      details.StatusCode,
// 						ResponsePreview: details.ResponsePreview,
// 						ResponseHeaders: details.ResponseHeaders,
// 						CurlPocCommand:  BuildCurlCmd(job.Method, job.URL, payload.HeadersToMap(job.Headers)),
// 						BypassModule:    job.BypassMode,
// 						ContentType:     details.ContentType,
// 						ContentLength:   details.ContentLength,
// 						ResponseBytes:   details.ResponseBytes,
// 						Title:           details.Title,
// 						ServerInfo:      details.ServerInfo,
// 						RedirectURL:     details.RedirectURL,
// 					}
// 				}
// 			}
// 		}
// 	}
// }
