package cli

import (
	"fmt"
	"path/filepath"
	"sort"

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

	// Initialize the scanner if it's nil
	if r.Scanner == nil {
		scannerOpts := &scanner.ScannerOpts{
			BypassModule:              r.RunnerOptions.Module,
			OutDir:                    r.RunnerOptions.OutDir,
			Timeout:                   r.RunnerOptions.Timeout,
			Threads:                   r.RunnerOptions.Threads,
			Delay:                     r.RunnerOptions.Delay,
			MaxRetries:                r.RunnerOptions.MaxRetries,
			RetryDelay:                r.RunnerOptions.RetryDelay,
			MaxConsecutiveFailedReqs:  r.RunnerOptions.MaxConsecutiveFailedReqs,
			Proxy:                     "",
			EnableHTTP2:               r.RunnerOptions.EnableHTTP2,
			SpoofHeader:               r.RunnerOptions.SpoofHeader,
			SpoofIP:                   r.RunnerOptions.SpoofIP,
			FollowRedirects:           r.RunnerOptions.FollowRedirects,
			MatchStatusCodes:          r.RunnerOptions.MatchStatusCodes,
			Debug:                     r.RunnerOptions.Debug,
			Verbose:                   r.RunnerOptions.Verbose,
			ResponseBodyPreviewSize:   r.RunnerOptions.ResponseBodyPreviewSize,
			DisableStreamResponseBody: r.RunnerOptions.DisableStreamResponseBody,
			ResendRequest:             r.RunnerOptions.ResendRequest,
		}
		r.Scanner = scanner.NewScanner(scannerOpts, []string{data.FullURL})
	}

	// Create results channel
	results := make(chan *scanner.Result, 1)

	// Signal the scanner to resend the request
	go func() {
		defer close(results) // Ensure the channel is closed after processing
		r.Scanner.ResendRequestWithDebugToken(r.RunnerOptions.ResendRequest, results)
	}()

	// Process the result
	var allFindings []*scanner.Result
	for result := range results {
		if result != nil {
			allFindings = append(allFindings, result)
		}
	}

	// If we have any findings, sort and save them
	if len(allFindings) > 0 {
		// Sort findings by status code and then by module
		sort.Slice(allFindings, func(i, j int) bool {
			if allFindings[i].StatusCode != allFindings[j].StatusCode {
				return allFindings[i].StatusCode < allFindings[j].StatusCode
			}
			return allFindings[i].BypassModule < allFindings[j].BypassModule
		})

		// Save findings first
		outputFile := filepath.Join(r.RunnerOptions.OutDir, "findings.json")
		if err := scanner.AppendResultsToJSON(outputFile, data.FullURL, data.BypassModule, allFindings); err != nil {
			GB403Logger.Error().Msgf("Failed to save findings for %s: %v\n", data.FullURL, err)
		}

		// Print results only once
		fmt.Println()
		scanner.PrintResultsTable(data.FullURL, allFindings)

		fmt.Println()
		GB403Logger.Success().Msgf("Results saved to %s\n\n", outputFile)
	}

	return nil
}
