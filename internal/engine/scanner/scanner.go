package scanner

import (
	"github.com/slicingmelon/go-bypass-403/internal/cli"
	"github.com/slicingmelon/go-bypass-403/internal/engine/scanner"
	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

type Scanner struct {
	opts *cli.Options
	urls []string
}

func New(opts *cli.Options, urls []string) *Scanner {
	return &Scanner{
		opts: opts,
		urls: urls,
	}
}

func (s *Scanner) Run() error {
	logger.Info("Initializing scanner with %d URLs", len(s.urls))

	// For each URL, run the core scanner
	for _, url := range s.urls {
		results := scanner.RunAllBypasses(url)

		// Process results
		for result := range results {
			if err := s.processResult(result); err != nil {
				logger.Error("Error processing result for %s: %v", url, err)
			}
		}
	}

	return nil
}

func (s *Scanner) processResult(result *scanner.Result) error {
	// Process and save/display results
	return nil
}
