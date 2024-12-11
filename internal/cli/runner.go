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

	// Step 2: Initialize URL Processor
	r.urlProcessor = NewURLProcessor(opts)

	// Step 3: Process and validate URLs
	urls, err := r.urlProcessor.ProcessURLs()
	if err != nil {
		return err
	}
	r.urls = urls
	logger.Info("Successfully processed %d URLs", len(urls))

	// Step 4: Initialize scanner with processed URLs
	r.scanner = scanner.New(opts, urls)

	return nil
}

func (r *Runner) Run() error {
	logger.Info("Starting scan with %d URLs", len(r.urls))
	return r.scanner.Run()
}
