package scanner

import (
	"fmt"
	"path/filepath"

	"github.com/slicingmelon/go-bypass-403/internal/engine/probe"
	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

type ScannerOpts struct {
	Timeout          int
	Threads          int
	MatchStatusCodes []int
	Debug            bool
	Verbose          bool
	BypassModule     string
	OutDir           string
	Delay            int
	TraceRequests    bool
	Proxy            string
	ForceHTTP2       bool
	SpoofHeader      string
	SpoofIP          string
	FollowRedirects  bool
	ProbeCache       probe.Cache
}

type Scanner struct {
	config *ScannerOpts
	urls   []string
}

func New(opts *ScannerOpts, urls []string) *Scanner {
	return &Scanner{
		config: opts,
		urls:   urls,
	}
}

func (s *Scanner) Run() error {
	logger.LogInfo("Initializing scanner with %d URLs", len(s.urls))

	for _, url := range s.urls {
		if err := s.scanURL(url); err != nil {
			logger.LogError("Error scanning %s: %v", url, err)
			continue
		}
	}
	return nil
}

func (s *Scanner) scanURL(url string) error {
	results := RunAllBypasses(url)
	var findings []*Result

	for result := range results {
		findings = append(findings, result)
	}

	if len(findings) > 0 {
		PrintTableHeader(url)
		for _, result := range findings {
			PrintTableRow(result)
		}
		fmt.Printf("\n")

		outputFile := filepath.Join(s.config.OutDir, "findings.json")
		if err := AppendResultsToJSON(outputFile, url, s.config.BypassModule, findings); err != nil {
			logger.LogError("Failed to save JSON results: %v", err)
		} else {
			logger.LogYellow("[+] Results appended to %s\n", outputFile)
		}
	} else {
		logger.LogOrange("\n[!] Sorry, no bypasses found for %s\n", url)
	}

	return nil
}
