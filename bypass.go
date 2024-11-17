// bypass.go
package main

import (
	"strings"
	"sync"
	"time"

	"github.com/slicingmelon/go-rawurlparser"
)

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
	jobBuffer := config.Threads * 30
	jobs := make(chan PayloadJob, jobBuffer)
	var wg sync.WaitGroup

	// Start workers first
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results)
	}

	// Generate jobs in a goroutine
	go func() {
		generateMidPathsJobs(targetURL, jobs)
		close(jobs)
	}()

	wg.Wait()
}

func runHeaderIPBypass(targetURL string, results chan<- *Result) {
	jobBuffer := config.Threads * 5
	jobs := make(chan PayloadJob, jobBuffer)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results)
	}

	// Generate jobs
	go func() {
		generateHeaderIPJobs(targetURL, jobs)
		close(jobs)
	}()

	wg.Wait()
}

func runEndPathsBypass(targetURL string, results chan<- *Result) {
	jobBuffer := config.Threads * 5
	jobs := make(chan PayloadJob, jobBuffer)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results)
	}

	// Generate jobs
	go func() {
		generateEndPathsJobs(targetURL, jobs)
		close(jobs)
	}()

	wg.Wait()
}

func runCaseSubstitutionBypass(targetURL string, results chan<- *Result) {
	jobBuffer := config.Threads * 5
	jobs := make(chan PayloadJob, jobBuffer)
	var wg sync.WaitGroup

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results)
	}

	go func() {
		generateCaseSubstitutionJobs(targetURL, jobs)
		close(jobs)
	}()

	wg.Wait()
}

func runCharEncodeBypass(targetURL string, results chan<- *Result) {
	jobBuffer := config.Threads * 5
	jobs := make(chan PayloadJob, jobBuffer)
	var wg sync.WaitGroup

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results)
	}

	go func() {
		generateCharEncodeJobs(targetURL, jobs)
		close(jobs)
	}()

	wg.Wait()
}

func runHeaderSchemeBypass(targetURL string, results chan<- *Result) {
	jobBuffer := config.Threads * 5
	jobs := make(chan PayloadJob, jobBuffer)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results)
	}

	// Generate jobs
	go func() {
		generateHeaderSchemeJobs(targetURL, jobs)
		close(jobs)
	}()

	wg.Wait()
}

func runHeaderURLBypass(targetURL string, results chan<- *Result) {
	jobBuffer := config.Threads * 5
	jobs := make(chan PayloadJob, jobBuffer)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results)
	}

	// Generate jobs
	go func() {
		generateHeaderURLJobs(targetURL, jobs)
		close(jobs)
	}()

	wg.Wait()
}

func runHeaderPortBypass(targetURL string, results chan<- *Result) {
	jobBuffer := config.Threads * 5
	jobs := make(chan PayloadJob, jobBuffer)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results)
	}

	// Generate jobs
	go func() {
		generateHeaderPortJobs(targetURL, jobs)
		close(jobs)
	}()

	wg.Wait()
}

func worker(wg *sync.WaitGroup, jobs <-chan PayloadJob, results chan<- *Result) {
	defer wg.Done()
	limiter := time.Tick(time.Millisecond * 100) // Add rate limiting
	for job := range jobs {
		<-limiter // Wait for rate limit
		details, err := sendRequest(job.method, job.url, job.headers, job.bypassMode)
		if err == nil {
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
