package cli

import (
	"github.com/slicingmelon/go-bypass-403/internal/engine/scanner"
	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

type Runner struct {
	options      *Options
	urls         []string
	scanner      *scanner.Scanner
	urlProcessor *URLProcessor
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
		logger.EnableVerbose()
	}
	if opts.Debug {
		logger.EnableDebug()
	}

	// Step 2: Initialize URL Processor
	r.urlProcessor = NewURLProcessor(opts)

	// Step 3: Process and validate URLs
	urls, err := r.urlProcessor.ProcessURLs()
	if err != nil {
		return err
	}
	r.urls = urls

	// Step 4: Initialize scanner with processed URLs
	scannerOpts := &scanner.ScannerOpts{
		BypassModule:            r.options.Module,
		OutDir:                  r.options.OutDir,
		Timeout:                 r.options.Timeout,
		Threads:                 r.options.Threads,
		Delay:                   r.options.Delay,
		TraceRequests:           r.options.TraceRequests,
		Proxy:                   r.options.ParsedProxy.String(),
		EnableHTTP2:             r.options.EnableHTTP2,
		SpoofHeader:             r.options.SpoofHeader,
		SpoofIP:                 r.options.SpoofIP,
		FollowRedirects:         r.options.FollowRedirects,
		MatchStatusCodes:        r.options.MatchStatusCodes,
		Debug:                   r.options.Debug,
		Verbose:                 r.options.Verbose,
		ResponseBodyPreviewSize: r.options.ResponseBodyPreviewSize,
		ProbeCache:              r.urlProcessor.GetProbeCache(),
	}

	r.scanner = scanner.New(scannerOpts, urls)
	return nil
}

func (r *Runner) Run() error {
	return r.scanner.Run()
}
