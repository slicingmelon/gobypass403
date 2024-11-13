// bypass.go
package main

import (
	"sync"
)

func RunAllBypasses(targetURL string) chan *Result {
	results := make(chan *Result)

	go func() {
		if config.Mode == ModeAll || config.Mode == ModeMidPaths {
			runMidPathsBypass(targetURL, results)
		}
		if config.Mode == ModeAll || config.Mode == ModeEndPaths {
			runEndPathsBypass(targetURL, results)
		}
		if config.Mode == ModeAll || config.Mode == ModeCaseSubstitution {
			runCaseSubstitutionBypass(targetURL, results)
		}
		if config.Mode == ModeAll || config.Mode == ModeCharEncode {
			runCharEncodeBypass(targetURL, results)
		}
		if config.Mode == ModeAll || config.Mode == ModeHeadersIP {
			runHeaderIPBypass(targetURL, results)
		}
		if config.Mode == ModeAll || config.Mode == ModeHeadersScheme {
			runHeaderSchemeBypass(targetURL, results)
		}
		if config.Mode == ModeAll || config.Mode == ModeHeadersURL {
			runHeaderURLBypass(targetURL, results)
		}
		if config.Mode == ModeAll || config.Mode == ModeHeadersPort {
			runHeaderPortBypass(targetURL, results)
		}
		close(results)
	}()

	return results
}

func runMidPathsBypass(targetURL string, results chan<- *Result) {
	jobs := make(chan PayloadJob, 100)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go worker(&wg, jobs, results)
	}

	// Generate jobs
	go func() {
		generateMidPathsJobs(targetURL, jobs)
		close(jobs)
	}()

	wg.Wait()
}

func runHeaderIPBypass(targetURL string, results chan<- *Result) {
	jobs := make(chan PayloadJob, 100)
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
	jobs := make(chan PayloadJob, 100)
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
	jobs := make(chan PayloadJob, 100)
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
	jobs := make(chan PayloadJob, 100)
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
	jobs := make(chan PayloadJob, 100)
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
	jobs := make(chan PayloadJob, 100)
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
	jobs := make(chan PayloadJob, 100)
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
	for job := range jobs {
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
