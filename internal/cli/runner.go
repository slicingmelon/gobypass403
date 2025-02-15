package cli

import (
	"fmt"
	"path/filepath"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/scanner"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

type Runner struct {
	RunnerOptions *CliOptions
	Urls          []string
	Scanner       *scanner.Scanner
	UrlRecon      *URLRecon
}

func NewRunner() *Runner {
	// Initialize the singleton error handler
	_ = GB403ErrorHandler.GetErrorHandler(32)
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
		RequestDelay:             r.RunnerOptions.Delay,
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
	errHandler := GB403ErrorHandler.GetErrorHandler()

	// Decode the token
	tokenData, err := payload.DecodeDebugToken(r.RunnerOptions.ResendRequest)
	if err != nil {
		return fmt.Errorf("failed to decode debug token: %w", err)
	}

	GB403Logger.Info().Msgf("Resending request %d times to: %s", r.RunnerOptions.ResendCount, tokenData.FullURL)

	// Create scanner with options
	scannerOpts := &scanner.ScannerOpts{
		Threads:                   r.RunnerOptions.Threads,
		Timeout:                   r.RunnerOptions.Timeout,
		MaxRetries:                r.RunnerOptions.MaxRetries,
		RetryDelay:                r.RunnerOptions.RetryDelay,
		MaxConsecutiveFailedReqs:  r.RunnerOptions.MaxConsecutiveFailedReqs,
		ResponseBodyPreviewSize:   r.RunnerOptions.ResponseBodyPreviewSize,
		Proxy:                     r.RunnerOptions.Proxy,
		OutDir:                    r.RunnerOptions.OutDir,
		RequestDelay:              r.RunnerOptions.RequestDelay,
		MatchStatusCodes:          r.RunnerOptions.MatchStatusCodes,
		EnableHTTP2:               r.RunnerOptions.EnableHTTP2,
		DisableStreamResponseBody: r.RunnerOptions.DisableStreamResponseBody,
	}

	s := scanner.NewScanner(scannerOpts, []string{tokenData.FullURL})
	defer s.Close()

	// Process the resend request
	findings, err := s.ResendRequestWithToken(r.RunnerOptions.ResendRequest, r.RunnerOptions.ResendCount)
	if err != nil {
		return fmt.Errorf("failed to process resend request: %w", err)
	}

	// Print results
	if len(findings) > 0 {
		scanner.PrintResultsTable(tokenData.FullURL, findings)
		fmt.Println()

		// Save findings
		outputFile := filepath.Join(r.RunnerOptions.OutDir, "findings.json")
		if err := scanner.AppendResultsToJson(outputFile, tokenData.FullURL, "resend_request", findings); err != nil {
			GB403Logger.Error().Msgf("Failed to save findings: %v\n", err)
		} else {
			GB403Logger.Success().Msgf("Scan for %s completed. Results saved to %s\n", tokenData.FullURL, outputFile)
		}
	} else {
		GB403Logger.Info().Msgf("No findings detected for %s", tokenData.FullURL)
	}

	// Print error stats
	fmt.Println()
	errHandler.PrintErrorStats()

	return nil
}
