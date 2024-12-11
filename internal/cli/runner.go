package cli

import (
	"github.com/slicingmelon/go-bypass-403/internal/engine/scanner"
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
		Timeout:          r.options.Timeout,
		Threads:          r.options.Threads,
		MatchStatusCodes: r.options.MatchStatusCodes,
		Debug:            r.options.Debug,
		Verbose:          r.options.Verbose,
	}

	r.scanner = scanner.New(scannerOpts, urls) // This will now work
	return nil
}

func (r *Runner) Run() error {
	scannerOpts := &scanner.ScannerOpts{
		Timeout:          r.options.Timeout,
		Threads:          r.options.Threads,
		MatchStatusCodes: r.options.MatchStatusCodes,
		Debug:            r.options.Debug,
		Verbose:          r.options.Verbose,
		//
	}

	scan := scanner.New(scannerOpts, r.urls)
	return scan.Run()
}
