package cli

import (
	"github.com/slicingmelon/go-bypass-403/internal/scanner"
	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

type Runner struct {
	options *Options
	scanner *scanner.Scanner
	urls    []string
}

func NewRunner() *Runner {
	return &Runner{}
}

func (r *Runner) Initialize() error {
	// Parse flags and get options
	opts, err := parseFlags()
	if err != nil {
		return err
	}
	r.options = opts

	// Process URLs
	urlProcessor := NewURLProcessor(opts)
	urls, err := urlProcessor.ProcessURLs()
	if err != nil {
		return err
	}
	r.urls = urls

	// Initialize scanner
	r.scanner = scanner.New(opts, urls)
	return nil
}

func (r *Runner) Run() error {
	logger.Info("Starting scan with %d URLs", len(r.urls))
	return r.scanner.Run()
}
