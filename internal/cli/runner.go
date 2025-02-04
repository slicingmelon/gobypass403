package cli

import (
	"fmt"

	"github.com/slicingmelon/go-bypass-403/internal/engine/scanner"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

type Runner struct {
	options  *CliOptions
	urls     []string
	scanner  *scanner.Scanner
	urlRecon *URLRecon
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
	r.options = opts

	// Enable Verbose and Debug Logging only when -v and/or -d are used
	if opts.Verbose {
		GB403Logger.DefaultLogger.EnableVerbose()
	}
	if opts.Debug {
		GB403Logger.DefaultLogger.EnableDebug()
	}

	// Step 2: Initialize URL Processor and process (recon) URLs
	r.urlRecon = NewURLRecon(r.options)
	urls, err := r.urlRecon.ProcessURLs()
	if err != nil {
		return fmt.Errorf("failed to process URLs: %w", err)
	}
	r.urls = urls

	// Step 4: Initialize scanner with processed URLs
	scannerOpts := &scanner.ScannerOpts{
		BypassModule:            r.options.Module,
		OutDir:                  r.options.OutDir,
		Timeout:                 r.options.Timeout,
		Threads:                 r.options.Threads,
		Delay:                   r.options.Delay,
		Proxy:                   "",
		EnableHTTP2:             r.options.EnableHTTP2,
		SpoofHeader:             r.options.SpoofHeader,
		SpoofIP:                 r.options.SpoofIP,
		FollowRedirects:         r.options.FollowRedirects,
		MatchStatusCodes:        r.options.MatchStatusCodes,
		Debug:                   r.options.Debug,
		Verbose:                 r.options.Verbose,
		ResponseBodyPreviewSize: r.options.ResponseBodyPreviewSize,
		ReconCache:              r.urlRecon.reconService.GetReconCache(),
	}

	// Only set proxy if ParsedProxy exists
	if r.options.ParsedProxy != nil {
		scannerOpts.Proxy = r.options.ParsedProxy.String()
	}

	r.scanner = scanner.NewScanner(scannerOpts, urls)
	return nil
}

func (r *Runner) Run() error {
	return r.scanner.Run()
}
