package config

import (
	"fmt"

	"github.com/slicingmelon/go-bypass-403/internal/engine/scanner"
)

type Scanner struct {
	opts *Options
	urls []string
}

func NewScanner(opts *Options, urls []string) (*Scanner, error) {
	return &Scanner{
		opts: opts,
		urls: urls,
	}, nil
}

func (s *Scanner) Run() error {
	// Print banner and configuration
	s.printBanner()
	s.opts.PrintConfiguration()

	LogYellow("[+] Total URLs to be scanned: %d\n", len(s.urls))

	// Run scans
	for _, url := range s.urls {
		if err := s.scanURL(url); err != nil {
			LogError("Error scanning %s: %v", url, err)
		}
	}

	return nil
}

func (s *Scanner) scanURL(url string) error {
	results := scanner.RunAllBypasses(url)
	var findings []*scanner.Result

	for result := range results {
		findings = append(findings, result)
	}

	return s.processFindings(url, findings)
}

func (s *Scanner) processFindings(url string, findings []*scanner.Result) error {
	if len(findings) > 0 {
		PrintTableHeader(url)
		for _, result := range findings {
			PrintTableRow(result)
		}
		fmt.Printf("\n")

		if err := SaveResults(s.opts.OutDir, url, s.opts.Mode, findings); err != nil {
			return fmt.Errorf("failed to save results: %v", err)
		}
	} else {
		LogOrange("\n[!] No bypasses found for %s\n", url)
	}
	return nil
}
