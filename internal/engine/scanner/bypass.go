package scanner

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/utils/errkit"
	"github.com/slicingmelon/go-bypass-403/internal/config"
	"github.com/slicingmelon/go-bypass-403/internal/utils"
	"github.com/slicingmelon/go-rawurlparser"
)

type WorkerContext struct {
	mode     string
	progress *utils.ProgressCounter
	cancel   chan struct{}
	wg       *sync.WaitGroup
	once     sync.Once
}

func NewWorkerContext(mode string, total int) *WorkerContext {
	return &WorkerContext{
		mode: mode,
		progress: &utils.ProgressCounter{
			total: total,
			mode:  mode,
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
func RunAllBypasses(targetURL string) chan *Result {
	results := make(chan *Result)

	// Validate URL, should remove this, it's validated already
	if _, err := rawurlparser.RawURLParse(targetURL); err != nil {
		LogError("Failed to parse URL: %s", targetURL)
		close(results)
		return results
	}

	go func() {
		modes := strings.Split(config.Mode, ",")
		for _, mode := range modes {
			mode = strings.TrimSpace(mode)

			// Skip if mode is not enabled in AvailableModes
			if !AvailableModes[mode].Enabled && mode != "all" {
				continue
			}

			// Run the appropriate bypass based on mode
			switch mode {
			case "all":
				// Run all enabled modes
				for modeName, modeConfig := range AvailableModes {
					if modeConfig.Enabled && modeName != "all" {
						runBypassForMode(modeName, targetURL, results)
					}
				}
			default:
				runBypassForMode(mode, targetURL, results)
			}
		}
		close(results)
	}()

	return results
}

func runBypassForMode(mode string, targetURL string, results chan<- *Result) {
	// First run the dumb check
	runDumbCheck(targetURL, results)

	switch mode {
	case "mid_paths":
		runMidPathsBypass(targetURL, results)
	case "end_paths":
		runEndPathsBypass(targetURL, results)
	case "case_substitution":
		runCaseSubstitutionBypass(targetURL, results)
	case "char_encode":
		runCharEncodeBypass(targetURL, results)
	case "http_headers_ip":
		runHeaderIPBypass(targetURL, results)
	case "http_headers_scheme":
		runHeaderSchemeBypass(targetURL, results)
	case "http_headers_url":
		runHeaderURLBypass(targetURL, results)
	case "http_headers_port":
		runHeaderPortBypass(targetURL, results)
	case "http_host":
		runHostHeaderBypass(targetURL, results)
	}
}

func runDumbCheck(targetURL string, results chan<- *Result) {
	jobs := make(chan PayloadJob, jobBufferSize)
	allJobs := generateDumbJob(targetURL)

	// Create WorkerContext
	ctx := NewWorkerContext("dumb_check", len(allJobs))

	// Start workers
	for i := 0; i < config.Threads; i++ {
		ctx.wg.Add(1)
		go worker(ctx, jobs, results)
	}

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

func runMidPathsBypass(targetURL string, results chan<- *Result) {
	jobs := make(chan PayloadJob, jobBufferSize)
	allJobs := generateMidPathsJobs(targetURL)

	// Create WorkerContext
	ctx := NewWorkerContext("mid_paths", len(allJobs))

	// Start workers
	for i := 0; i < config.Threads; i++ {
		ctx.wg.Add(1)
		go worker(ctx, jobs, results)
	}

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

func runEndPathsBypass(targetURL string, results chan<- *Result) {
	jobs := make(chan PayloadJob, jobBufferSize)
	allJobs := generateEndPathsJobs(targetURL)

	// Create WorkerContext
	ctx := NewWorkerContext("end_paths", len(allJobs))

	// Start workers
	for i := 0; i < config.Threads; i++ {
		ctx.wg.Add(1)
		go worker(ctx, jobs, results)
	}

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

func runHeaderIPBypass(targetURL string, results chan<- *Result) {
	jobs := make(chan PayloadJob, jobBufferSize)
	allJobs := generateHeaderIPJobs(targetURL)

	// Create WorkerContext
	ctx := NewWorkerContext("http_headers_ip", len(allJobs))

	// Start workers with ctx
	for i := 0; i < config.Threads; i++ {
		ctx.wg.Add(1)
		go worker(ctx, jobs, results)
	}

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

func runCaseSubstitutionBypass(targetURL string, results chan<- *Result) {
	jobs := make(chan PayloadJob, jobBufferSize)
	allJobs := generateCaseSubstitutionJobs(targetURL)

	// Create WorkerContext
	ctx := NewWorkerContext("case_substitution", len(allJobs))

	// Start workers with ctx
	for i := 0; i < config.Threads; i++ {
		ctx.wg.Add(1)
		go worker(ctx, jobs, results)
	}

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

func runCharEncodeBypass(targetURL string, results chan<- *Result) {
	jobs := make(chan PayloadJob, jobBufferSize)
	allJobs := generateCharEncodeJobs(targetURL)

	// Create WorkerContext
	ctx := NewWorkerContext("char_encode", len(allJobs))

	// Start workers with ctx
	for i := 0; i < config.Threads; i++ {
		ctx.wg.Add(1)
		go worker(ctx, jobs, results)
	}

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

func runHeaderSchemeBypass(targetURL string, results chan<- *Result) {
	jobs := make(chan PayloadJob, jobBufferSize)
	allJobs := generateHeaderSchemeJobs(targetURL)

	// Create WorkerContext
	ctx := NewWorkerContext("http_headers_scheme", len(allJobs))

	// Start workers with ctx
	for i := 0; i < config.Threads; i++ {
		ctx.wg.Add(1)
		go worker(ctx, jobs, results)
	}

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

func runHeaderURLBypass(targetURL string, results chan<- *Result) {
	jobs := make(chan PayloadJob, jobBufferSize)
	allJobs := generateHeaderURLJobs(targetURL)

	// Create WorkerContext
	ctx := NewWorkerContext("http_headers_url", len(allJobs))

	// Start workers with ctx
	for i := 0; i < config.Threads; i++ {
		ctx.wg.Add(1)
		go worker(ctx, jobs, results)
	}

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

func runHeaderPortBypass(targetURL string, results chan<- *Result) {
	jobs := make(chan PayloadJob, jobBufferSize)
	allJobs := generateHeaderPortJobs(targetURL)

	// Create WorkerContext
	ctx := NewWorkerContext("http_headers_port", len(allJobs))

	// Start workers with ctx
	for i := 0; i < config.Threads; i++ {
		ctx.wg.Add(1)
		go worker(ctx, jobs, results)
	}

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

func runHostHeaderBypass(targetURL string, results chan<- *Result) {
	jobs := make(chan PayloadJob, jobBufferSize)
	allJobs := generateHostHeaderJobs(targetURL)

	// Create WorkerContext
	ctx := NewWorkerContext("http_host", len(allJobs))

	// Start workers
	for i := 0; i < config.Threads; i++ {
		ctx.wg.Add(1)
		go worker(ctx, jobs, results)
	}

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

func worker(ctx *WorkerContext, jobs <-chan PayloadJob, results chan<- *Result) {
	defer ctx.wg.Done()

	// Add panic recovery
	defer func() {
		if r := recover(); r != nil {
			LogError("[%s] Worker panic recovered: %v", ctx.mode, r)
			ctx.Stop()
		}
	}()

	// Create client
	client, err := New(&config, ctx.mode)
	if err != nil {
		LogError("Failed to create client for mode %s: %v", ctx.mode, err)
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
					LogError("[%s] Failed to parse URL: %s", job.bypassMode, job.url)
					continue
				}

				if errkit.IsKind(err, ErrKindGo403BypassFatal) {
					if config.Verbose {
						LogError("[ErrorMonitorService] => Stopping current bypass mode [%s] -- Permanent error for %s: %v",
							job.bypassMode, job.url, err)
					}
					ctx.Stop()
					return
				}

				LogError("[%s] Request error for %s: %v",
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
						CurlPocCommand:  buildCurlCmd(job.method, job.url, headersToMap(job.headers)),
						BypassMode:      job.bypassMode,
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
