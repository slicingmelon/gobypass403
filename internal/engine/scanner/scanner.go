package scanner

import (
	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

type ScannerOpts struct {
	Timeout          int
	Threads          int
	MatchStatusCodes []int
	Debug            bool
	Verbose          bool
}

type Scanner struct {
	config *ScannerOpts
	urls   []string
}

func New(cfg *ScannerOpts, urls []string) *Scanner {
	return &Scanner{
		config: cfg,
		urls:   urls,
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
