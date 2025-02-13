package cli

import (
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp"
	"github.com/slicingmelon/go-bypass-403/internal/engine/scanner"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	rawurlparser "github.com/slicingmelon/go-rawurlparser"
)

type Runner struct {
	RunnerOptions *CliOptions
	Urls          []string
	Scanner       *scanner.Scanner
	UrlRecon      *URLRecon
}

func NewRunner() *Runner {
	return &Runner{}
}

func (r *Runner) Initialize() error {
	// Step 1: Parse CLI flags
	opts, err := parseFlags()
	if err != nil {
		return err
	}
	r.RunnerOptions = opts

	if opts.Verbose {
		GB403Logger.DefaultLogger.EnableVerbose()
	}
	if opts.Debug {
		GB403Logger.DefaultLogger.EnableDebug()
	}

	// Handle resend request immediately if specified
	if opts.ResendRequest != "" {
		if opts.URL != "" || opts.URLsFile != "" || opts.SubstituteHostsFile != "" {
			return fmt.Errorf("--resend cannot be used with -u/--url or -l/--url-file or -s/--substitute-hosts-file")
		}
		return r.handleResendRequest()
	}

	// Step 2: Initialize URL Processor and process (recon) URLs
	r.UrlRecon = NewURLRecon(r.RunnerOptions)
	urls, err := r.UrlRecon.ProcessURLs()
	if err != nil {
		return fmt.Errorf("failed to process URLs: %w", err)
	}

	r.Urls = urls

	// Step 4: Initialize scanner with processed URLs
	scannerOpts := &scanner.ScannerOpts{
		BypassModule:             r.RunnerOptions.Module,
		OutDir:                   r.RunnerOptions.OutDir,
		Timeout:                  r.RunnerOptions.Timeout,
		Threads:                  r.RunnerOptions.Threads,
		Delay:                    r.RunnerOptions.Delay,
		MaxRetries:               r.RunnerOptions.MaxRetries,
		RetryDelay:               r.RunnerOptions.RetryDelay,
		MaxConsecutiveFailedReqs: r.RunnerOptions.MaxConsecutiveFailedReqs,
		Proxy:                    "",
		EnableHTTP2:              r.RunnerOptions.EnableHTTP2,

		SpoofHeader:               r.RunnerOptions.SpoofHeader,
		SpoofIP:                   r.RunnerOptions.SpoofIP,
		FollowRedirects:           r.RunnerOptions.FollowRedirects,
		MatchStatusCodes:          r.RunnerOptions.MatchStatusCodes,
		Debug:                     r.RunnerOptions.Debug,
		Verbose:                   r.RunnerOptions.Verbose,
		ResponseBodyPreviewSize:   r.RunnerOptions.ResponseBodyPreviewSize,
		DisableStreamResponseBody: r.RunnerOptions.DisableStreamResponseBody,
		ResendRequest:             r.RunnerOptions.ResendRequest,

		ReconCache: r.UrlRecon.reconService.GetReconCache(),
	}

	// Only set proxy if ParsedProxy exists
	if r.RunnerOptions.ParsedProxy != nil {
		scannerOpts.Proxy = r.RunnerOptions.ParsedProxy.String()
	}

	r.Scanner = scanner.NewScanner(scannerOpts, urls)

	return nil
}

func (r *Runner) Run() error {
	// If resend request was handled in Initialize, exit here
	if r.RunnerOptions.ResendRequest != "" {
		return nil
	}

	// Normal scanning mode
	return r.Scanner.Run()
}

func (r *Runner) handleResendRequest() error {
	// Decode the token
	data, err := payload.DecodeDebugToken(r.RunnerOptions.ResendRequest)
	if err != nil {
		return fmt.Errorf("failed to decode debug token: %w", err)
	}

	GB403Logger.Debug().Msgf("Decoded token data: %+v", data)

	// Parse the URL using rawurlparser
	parsedURL, err := rawurlparser.RawURLParse(data.FullURL)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}

	// Create the job with all required fields
	job := payload.PayloadJob{
		FullURL:      data.FullURL,
		Method:       "GET",
		Host:         parsedURL.Host,
		Scheme:       parsedURL.Scheme,
		RawURI:       parsedURL.Path,
		Headers:      data.Headers,
		BypassModule: "resend_request",
		PayloadToken: payload.GenerateDebugToken(payload.SeedData{FullURL: data.FullURL}),
	}

	GB403Logger.Debug().Msgf("Created job: method=%s scheme=%s host=%s rawuri=%s",
		job.Method, job.Scheme, job.Host, job.RawURI)

	// Create results channel with buffer
	results := make(chan *scanner.Result, 1)
	var wg sync.WaitGroup
	wg.Add(2)

	// Slice to store findings
	var allFindings []*scanner.Result
	var findingsMutex sync.Mutex

	GB403Logger.Info().Msgf("Resending request to: %s", data.FullURL)

	// Create worker directly without initializing full scanner
	httpClientOpts := &rawhttp.HTTPClientOptions{
		Timeout:                 time.Duration(r.RunnerOptions.Timeout) * time.Millisecond,
		MaxConnsPerHost:         r.RunnerOptions.Threads + (r.RunnerOptions.Threads / 2),
		ResponseBodyPreviewSize: r.RunnerOptions.ResponseBodyPreviewSize,
		ProxyURL:                r.RunnerOptions.Proxy,
	}

	worker := rawhttp.NewRequestWorkerPool(httpClientOpts, 1, GB403ErrorHandler.NewErrorHandler(32))
	defer worker.Close()

	// Start the results collector goroutine
	go func() {
		defer wg.Done()
		for result := range results {
			if result != nil {
				findingsMutex.Lock()
				allFindings = append(allFindings, result)
				findingsMutex.Unlock()

				scanner.PrintResultsTable(data.FullURL, []*scanner.Result{result})
				GB403Logger.Debug().Msgf("Received result with status code: %d", result.StatusCode)
			}
		}
	}()

	// Start the request sender goroutine
	go func() {
		defer wg.Done()
		defer close(results)

		GB403Logger.Debug().Msgf("Processing request...")

		// Process request directly
		responses := worker.ProcessRequests([]payload.PayloadJob{job})

		responseReceived := false
		for response := range responses {
			responseReceived = true
			if response == nil {
				GB403Logger.Debug().Msgf("Received nil response")
				continue
			}

			GB403Logger.Debug().Msgf("Received response with status code: %d", response.StatusCode)

			result := &scanner.Result{
				TargetURL:       string(response.URL),
				BypassModule:    job.BypassModule,
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
				ResponseTime:    response.ResponseTime,
				DebugToken:      string(response.DebugToken),
			}

			results <- result
			rawhttp.ReleaseResponseDetails(response)
		}

		if !responseReceived {
			GB403Logger.Warning().Msgf("No response was received from the request pool")
		}
	}()

	// Wait for both goroutines to complete
	wg.Wait()

	// Process findings
	findingsMutex.Lock()
	defer findingsMutex.Unlock()

	if len(allFindings) > 0 {
		outputFile := filepath.Join(r.RunnerOptions.OutDir, "findings.json")
		if err := scanner.AppendResultsToJSON(outputFile, data.FullURL, data.BypassModule, allFindings); err != nil {
			GB403Logger.Error().Msgf("Failed to save findings for %s: %v", data.FullURL, err)
		}
		GB403Logger.Success().Msgf("Results saved to %s", outputFile)
	} else {
		GB403Logger.Warning().Msgf("No results received from request")
	}

	return nil
}
