package scanner

import (
	"github.com/slicingmelon/go-bypass-403/internal/cli"
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

	// URLs are already processed and validated by URLProcessor
	for _, url := range s.urls {
		if err := s.scanURL(url); err != nil {
			logger.Error("Error scanning %s: %v", url, err)
			continue
		}
	}
	return nil
}

func (s *Scanner) scanURL(url string) error {
	// Your scanning logic here
	return nil
}
