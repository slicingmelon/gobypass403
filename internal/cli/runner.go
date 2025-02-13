package cli

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/scanner"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
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

	// Print the decoded information
	fmt.Println("=== Debug Token Information ===")
	fmt.Printf("Full URL: %s\n", data.FullURL)
	fmt.Printf("Bypass Module: %s\n", data.BypassModule)
	fmt.Println("Headers:")
	for _, h := range data.Headers {
		fmt.Printf("  %s: %s\n", h.Header, h.Value)
	}

	// Set a default bypass module if empty
	if data.BypassModule == "" {
		data.BypassModule = "resend_request"
	}

	// Initialize the scanner if it's nil
	if r.Scanner == nil {
		scannerOpts := &scanner.ScannerOpts{
			BypassModule:              data.BypassModule, // Use the module from the token
			OutDir:                    r.RunnerOptions.OutDir,
			Timeout:                   r.RunnerOptions.Timeout,
			Threads:                   1, // Only need 1 thread for resend
			Delay:                     r.RunnerOptions.Delay,
			MaxRetries:                r.RunnerOptions.MaxRetries,
			RetryDelay:                r.RunnerOptions.RetryDelay,
			MaxConsecutiveFailedReqs:  r.RunnerOptions.MaxConsecutiveFailedReqs,
			Proxy:                     r.RunnerOptions.Proxy,
			EnableHTTP2:               r.RunnerOptions.EnableHTTP2,
			SpoofHeader:               r.RunnerOptions.SpoofHeader,
			SpoofIP:                   r.RunnerOptions.SpoofIP,
			FollowRedirects:           r.RunnerOptions.FollowRedirects,
			MatchStatusCodes:          r.RunnerOptions.MatchStatusCodes,
			Debug:                     r.RunnerOptions.Debug,
			Verbose:                   r.RunnerOptions.Verbose,
			ResponseBodyPreviewSize:   r.RunnerOptions.ResponseBodyPreviewSize,
			DisableStreamResponseBody: r.RunnerOptions.DisableStreamResponseBody,
		}
		r.Scanner = scanner.NewScanner(scannerOpts, []string{data.FullURL})
	}

	// Create results channel with buffer
	results := make(chan *scanner.Result, 1)

	// Create a WaitGroup for both sending and collecting results
	var wg sync.WaitGroup
	wg.Add(2) // One for sending, one for collecting

	// Slice to store findings with mutex for safe concurrent access
	var allFindings []*scanner.Result
	var findingsMutex sync.Mutex

	GB403Logger.Info().Msgf("Resending request to: %s\n", data.FullURL)

	// Start the results collector goroutine
	go func() {
		defer wg.Done()
		for result := range results {
			if result != nil {
				findingsMutex.Lock()
				allFindings = append(allFindings, result)
				findingsMutex.Unlock()

				// Print result immediately
				scanner.PrintResultsTable(data.FullURL, []*scanner.Result{result})
				GB403Logger.Debug().Msgf("Received result with status code: %d\n", result.StatusCode)
			}
		}
	}()

	// Start the request sender goroutine
	go func() {
		defer wg.Done()
		defer close(results) // Close results channel when done sending
		GB403Logger.Debug().Msgf("Starting request...")
		r.Scanner.ResendRequestWithDebugToken(r.RunnerOptions.ResendRequest, results)
		GB403Logger.Debug().Msgf("Finished sending request")
	}()

	// Wait for both goroutines to complete
	wg.Wait()
	GB403Logger.Debug().Msgf("All goroutines completed")

	// Process findings
	findingsMutex.Lock()
	defer findingsMutex.Unlock()

	if len(allFindings) > 0 {
		outputFile := filepath.Join(r.RunnerOptions.OutDir, "findings.json")
		if err := scanner.AppendResultsToJSON(outputFile, data.FullURL, data.BypassModule, allFindings); err != nil {
			GB403Logger.Error().Msgf("Failed to save findings for %s: %v\n", data.FullURL, err)
		}
		GB403Logger.Success().Msgf("Results saved to %s\n", outputFile)
	} else {
		GB403Logger.Warning().Msgf("No results received from request")
	}

	return nil
}
