// bypass.go
package main

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/utils/errkit"
	"github.com/slicingmelon/go-rawurlparser"
)

// Core Function
func RunAllBypasses(targetURL string) chan *Result {
	results := make(chan *Result)

	// Validate URL, should remove this, it's validated already
	if parsedURL := rawurlparser.RawURLParse(targetURL); parsedURL == nil {
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
	}
}

func runMidPathsBypass(targetURL string, results chan<- *Result) {
	jobs := make(chan PayloadJob, jobBufferSize)
	var wg sync.WaitGroup

	// Get all jobs upfront
	allJobs := generateMidPathsJobs(targetURL)

	// Create progress counter
	progress := &ProgressCounter{
		total: len(allJobs),
		mode:  "mid_paths",
	}

	// Start workers
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results, progress)
	}

	// Send jobs
	for _, job := range allJobs {
		jobs <- job
	}
	close(jobs)

	wg.Wait()
	fmt.Println()
}

func runEndPathsBypass(targetURL string, results chan<- *Result) {
	jobs := make(chan PayloadJob, jobBufferSize)
	var wg sync.WaitGroup

	// Get all jobs upfront
	allJobs := generateEndPathsJobs(targetURL)

	// Create progress counter
	progress := &ProgressCounter{
		total: len(allJobs),
		mode:  "end_paths",
	}

	// Start workers with progress counter
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results, progress)
	}

	// Send jobs
	for _, job := range allJobs {
		jobs <- job
	}
	close(jobs)

	wg.Wait()
	fmt.Println()
}

func runHeaderIPBypass(targetURL string, results chan<- *Result) {
	jobs := make(chan PayloadJob, jobBufferSize)
	var wg sync.WaitGroup

	// Get all jobs upfront
	allJobs := generateHeaderIPJobs(targetURL)

	// Create progress counter
	progress := &ProgressCounter{
		total: len(allJobs),
		mode:  "http_headers_ip",
	}

	// Start workers with progress counter
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results, progress)
	}

	// Send jobs
	for _, job := range allJobs {
		jobs <- job
	}
	close(jobs)

	wg.Wait()
	fmt.Println()
}

func runCaseSubstitutionBypass(targetURL string, results chan<- *Result) {
	jobs := make(chan PayloadJob, jobBufferSize)
	var wg sync.WaitGroup

	// Get all jobs upfront
	allJobs := generateCaseSubstitutionJobs(targetURL)

	// Create progress counter
	progress := &ProgressCounter{
		total: len(allJobs),
		mode:  "case_substitution",
	}

	// Start workers with progress counter
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results, progress)
	}

	// Send jobs
	for _, job := range allJobs {
		jobs <- job
	}
	close(jobs)

	wg.Wait()
	fmt.Println()
}

func runCharEncodeBypass(targetURL string, results chan<- *Result) {
	jobs := make(chan PayloadJob, jobBufferSize)
	var wg sync.WaitGroup

	// Get all jobs upfront
	allJobs := generateCharEncodeJobs(targetURL)

	// Create progress counter
	progress := &ProgressCounter{
		total: len(allJobs),
		mode:  "char_encode",
	}

	// Start workers with progress counter
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results, progress)
	}

	// Send jobs
	for _, job := range allJobs {
		jobs <- job
	}
	close(jobs)

	wg.Wait()
	fmt.Println()
}

func runHeaderSchemeBypass(targetURL string, results chan<- *Result) {
	jobs := make(chan PayloadJob, jobBufferSize)
	var wg sync.WaitGroup

	// Get all jobs upfront
	allJobs := generateHeaderSchemeJobs(targetURL)

	// Create progress counter
	progress := &ProgressCounter{
		total: len(allJobs),
		mode:  "http_headers_scheme",
	}

	// Start workers with progress counter
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results, progress)
	}

	// Send jobs
	for _, job := range allJobs {
		jobs <- job
	}
	close(jobs)

	wg.Wait()
	fmt.Println()
}

func runHeaderURLBypass(targetURL string, results chan<- *Result) {
	jobs := make(chan PayloadJob, jobBufferSize)
	var wg sync.WaitGroup

	// Get all jobs upfront
	allJobs := generateHeaderURLJobs(targetURL)

	// Create progress counter
	progress := &ProgressCounter{
		total: len(allJobs),
		mode:  "http_headers_url",
	}

	// Start workers with progress counter
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results, progress)
	}

	// Send jobs
	for _, job := range allJobs {
		jobs <- job
	}
	close(jobs)

	wg.Wait()
	fmt.Println()
}

func runHeaderPortBypass(targetURL string, results chan<- *Result) {
	jobs := make(chan PayloadJob, jobBufferSize)
	var wg sync.WaitGroup

	// Get all jobs upfront
	allJobs := generateHeaderPortJobs(targetURL)

	// Create progress counter
	progress := &ProgressCounter{
		total: len(allJobs),
		mode:  "http_headers_port",
	}

	// Start workers with progress counter
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results, progress)
	}

	// Send jobs
	for _, job := range allJobs {
		jobs <- job
	}
	close(jobs)

	wg.Wait()
	fmt.Println()
}

func worker(wg *sync.WaitGroup, jobs <-chan PayloadJob, results chan<- *Result, progress *ProgressCounter) {
	defer wg.Done()

	workerLimiter := time.NewTicker(time.Duration(config.Delay) * time.Millisecond)
	defer workerLimiter.Stop()

	for job := range jobs {
		<-workerLimiter.C
		details, err := sendRequest(job.method, job.url, job.headers, job.bypassMode)
		if progress != nil {
			progress.increment()
		}

		if err != nil {
			_, parseErr := rawurlparser.RawURLParseWithError(job.url)
			if parseErr != nil {
				LogError("[%s] Failed to parse URL: %s", job.bypassMode, job.url)
				continue
			}

			// Check if it's a permanent error
			if errkit.IsKind(err, errkit.ErrKindNetworkPermanent) {
				LogError("[ErrorMonitorService] => Stopping current bypass mode [%s] -- Permanent error for %s: %v",
					job.bypassMode, job.url, err)

				if progress != nil {
					progress.markAsCancelled() // New method to indicate cancellation
				}

				// Drain the jobs channel without updating progress
				go func() {
					for range jobs {
						// Just drain, don't increment
					}
				}()
				return // Stop this worker
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
