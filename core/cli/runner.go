/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package cli

import (
	"fmt"
	"path/filepath"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
	"github.com/slicingmelon/gobypass403/core/engine/scanner"
	GB403ErrorHandler "github.com/slicingmelon/gobypass403/core/utils/error"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

type Runner struct {
	RunnerOptions *CliOptions
	Urls          []string
	Scanner       *scanner.Scanner
	UrlRecon      *URLRecon
}

func NewRunner() *Runner {
	// Initialize the singleton error handler
	_ = GB403ErrorHandler.GetErrorHandler()
	return &Runner{}
}

func (r *Runner) Initialize() error {
	// Step 1: Parse CLI flags
	opts, err := parseFlags()
	if err != nil {
		return err
	}
	r.RunnerOptions = opts

	// Set ResultsDBFile if not already set
	if r.RunnerOptions.ResultsDBFile == "" {
		r.RunnerOptions.ResultsDBFile = filepath.Join(r.RunnerOptions.OutDir, "results.db")
	}

	// Initialize database to save results
	if err := scanner.InitDB(r.RunnerOptions.ResultsDBFile, r.RunnerOptions.ConcurrentRequests); err != nil {
		GB403Logger.Error().Msgf("Failed to initialize database: %v", err)
	}

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
		ResultsDBFile:            r.RunnerOptions.ResultsDBFile,
		Timeout:                  r.RunnerOptions.Timeout,
		ConcurrentRequests:       r.RunnerOptions.ConcurrentRequests,
		RequestDelay:             r.RunnerOptions.Delay,
		MaxRetries:               r.RunnerOptions.MaxRetries,
		RetryDelay:               r.RunnerOptions.RetryDelay,
		MaxConsecutiveFailedReqs: r.RunnerOptions.MaxConsecutiveFailedReqs,
		AutoThrottle:             r.RunnerOptions.AutoThrottle,
		Proxy:                    "",
		EnableHTTP2:              r.RunnerOptions.EnableHTTP2,

		SpoofHeader:               r.RunnerOptions.SpoofHeader,
		SpoofIP:                   r.RunnerOptions.SpoofIP,
		CustomHTTPHeaders:         r.RunnerOptions.CustomHTTPHeaders,
		FollowRedirects:           r.RunnerOptions.FollowRedirects,
		MatchStatusCodes:          r.RunnerOptions.MatchStatusCodes,
		MatchContentTypeBytes:     r.RunnerOptions.MatchContentTypeBytes,
		MinContentLength:          r.RunnerOptions.MinContentLength,
		MaxContentLength:          r.RunnerOptions.MaxContentLength,
		Debug:                     r.RunnerOptions.Debug,
		Verbose:                   r.RunnerOptions.Verbose,
		ResponseBodyPreviewSize:   r.RunnerOptions.ResponseBodyPreviewSize,
		DisableStreamResponseBody: r.RunnerOptions.DisableStreamResponseBody,
		DisableProgressBar:        r.RunnerOptions.DisableProgressBar,
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
	tokenData, err := payload.DecodePayloadToken(r.RunnerOptions.ResendRequest)
	if err != nil {
		return fmt.Errorf("failed to decode debug token: %w", err)
	}

	// Construct display URL for logging purposes
	targetURL := payload.BypassPayloadToBaseURL(payload.BypassPayload{
		Scheme: tokenData.Scheme,
		Host:   tokenData.Host,
	})
	GB403Logger.Info().Msgf("Resending request %d times to: %s\n", r.RunnerOptions.ResendNum, targetURL)

	//dbPath := filepath.Join(r.RunnerOptions.OutDir, "results.db")

	// Create scanner with options
	scannerOpts := &scanner.ScannerOpts{
		ConcurrentRequests:        r.RunnerOptions.ConcurrentRequests,
		Timeout:                   r.RunnerOptions.Timeout,
		MaxRetries:                r.RunnerOptions.MaxRetries,
		RetryDelay:                r.RunnerOptions.RetryDelay,
		MaxConsecutiveFailedReqs:  r.RunnerOptions.MaxConsecutiveFailedReqs,
		ResponseBodyPreviewSize:   r.RunnerOptions.ResponseBodyPreviewSize,
		AutoThrottle:              r.RunnerOptions.AutoThrottle,
		Proxy:                     r.RunnerOptions.Proxy,
		OutDir:                    r.RunnerOptions.OutDir,
		ResultsDBFile:             r.RunnerOptions.ResultsDBFile,
		RequestDelay:              r.RunnerOptions.RequestDelay,
		MatchStatusCodes:          r.RunnerOptions.MatchStatusCodes,
		CustomHTTPHeaders:         r.RunnerOptions.CustomHTTPHeaders,
		EnableHTTP2:               r.RunnerOptions.EnableHTTP2,
		DisableStreamResponseBody: r.RunnerOptions.DisableStreamResponseBody,
		DisableProgressBar:        r.RunnerOptions.DisableProgressBar,
	}

	// Initialize scanner with display URL for logging
	s := scanner.NewScanner(scannerOpts, []string{targetURL})
	defer s.Close()

	// Process the resend request
	findings, err := s.ResendRequestFromToken(r.RunnerOptions.ResendRequest, r.RunnerOptions.ResendNum)
	if err != nil {
		return fmt.Errorf("failed to process resend request: %w", err)
	}

	// Process results
	if len(findings) > 0 {
		// First save findings to DB
		if err := scanner.AppendResultsToDB(findings); err != nil {
			GB403Logger.Error().Msgf("Failed to save findings: %v\n", err)
		} else {
			GB403Logger.Success().Msgf("%d findings saved to %s\n",
				len(findings), r.RunnerOptions.ResultsDBFile)

			// Then print results from DB
			if err := scanner.PrintResultsTableFromDB(targetURL, tokenData.BypassModule); err != nil {
				GB403Logger.Error().Msgf("Failed to display results: %v\n", err)
			}
			fmt.Println()
		}
	} else {
		GB403Logger.Info().Msgf("No findings detected for %s\n", targetURL)
	}

	// Print error stats
	fmt.Println()
	errHandler.PrintErrorStats()

	return nil
}
