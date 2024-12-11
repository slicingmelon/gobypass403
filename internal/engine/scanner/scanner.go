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
	ProbeCache       probe.Cache
}

type Scanner struct {
	config *ScannerOpts
	urls   []string
}

type Result struct {
	TargetURL       string `json:"target_url"`
	BypassModule    string `json:"bypass_module"`
	CurlPocCommand  string `json:"curl_poc_command"`
	ResponseHeaders string `json:"response_headers"`
	ResponsePreview string `json:"response_preview"`
	StatusCode      int    `json:"response_status_code"`
	ContentType     string `json:"response_content_type"`
	ContentLength   int64  `json:"response_content_length"`
	ResponseBytes   int    `json:"response_bytes"`
	Title           string `json:"response_title"`
	ServerInfo      string `json:"response_server_info"`
	RedirectURL     string `json:"response_redirect_url"`
	HTMLFilename    string `json:"response_html_filename"`
}

type ScanResult struct {
	URL         string    `json:"url"`
	BypassModes string    `json:"bypass_modes"`
	ResultsPath string    `json:"results_path"`
	Results     []*Result `json:"results"`
}

type JSONData struct {
	Scans []ScanResult `json:"scans"`
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

	results := RunAllBypasses(url)
	var findings []*Result

	// Collect all results first
	for result := range results {
		findings = append(findings, result)
	}

	if len(findings) > 0 {
		PrintTableHeader(url)
		for _, result := range findings {
			PrintTableRow(result)
		}
		fmt.Printf("\n")

		// Save results to JSON immediately after processing each URL
		outputFile := filepath.Join(config.OutDir, "findings.json")
		if err := AppendResultsToJSON(outputFile, url, config.Mode, findings); err != nil {
			logger.LogError("Failed to save JSON results: %v", err)
		} else {
			logger.LogGreen("[+] Results appended to %s\n", outputFile)
		}
	} else {
		logger.LogOrange("\n[!] Sorry, no bypasses found for %s\n", url)
	}

	return nil
}
