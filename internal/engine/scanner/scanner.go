package scanner

import (
	"fmt"
	"path/filepath"

	"github.com/slicingmelon/go-bypass-403/internal/engine/probe"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

type ScannerOpts struct {
	Timeout                 int
	Threads                 int
	MatchStatusCodes        []int
	Debug                   bool
	Verbose                 bool
	BypassModule            string
	OutDir                  string
	Delay                   int
	TraceRequests           bool
	Proxy                   string
	EnableHTTP2             bool
	SpoofHeader             string
	SpoofIP                 string
	FollowRedirects         bool
	ResponseBodyPreviewSize int
	ProbeCache              probe.Cache
}

// Scanner represents the main scanner structure, perhaps the highest level in the hierarchy of the tool
type Scanner struct {
	config       *ScannerOpts
	urls         []string
	errorHandler *GB403ErrorHandler.ErrorHandler
}

// New creates a new Scanner instance
func New(opts *ScannerOpts, urls []string) *Scanner {
	return &Scanner{
		config:       opts,
		urls:         urls,
		errorHandler: GB403ErrorHandler.NewErrorHandler(),
	}
}

func (s *Scanner) Run() error {
	defer s.Close()

	logger.LogYellow("Initializing scanner with %d URLs", len(s.urls))

	for _, url := range s.urls {
		if err := s.scanURL(url); err != nil {
			logger.LogError("Error scanning %s: %v", url, err)
			if GB403ErrorHandler.IsPermanentError(err) {
				return err
			}
			continue
		}
	}
	return nil
}

func (s *Scanner) scanURL(url string) error {
	resultsChannel := s.RunAllBypasses(url)
	var findings []*Result

	// Collect all results first
	for result := range resultsChannel {
		if result != nil {
			findings = append(findings, result)
		}
	}

	// Then process and display them
	if len(findings) > 0 {
		PrintTableHeader(url)
		for _, result := range findings {
			PrintTableRow(result)
		}
		fmt.Printf("\n")

		outputFile := filepath.Join(s.config.OutDir, "findings.json")
		if err := AppendResultsToJSON(outputFile, url, s.config.BypassModule, findings); err != nil {
			handledErr := s.errorHandler.HandleError(url, err)
			logger.LogError("Failed to save JSON results: %v", handledErr)
			return handledErr
		}
		logger.LogYellow("[+] Results appended to %s\n", outputFile)
	} else {
		logger.LogOrange("\n[!] Sorry, no bypasses found for %s\n", url)
	}

	return nil
}

func (s *Scanner) Close() {
	// Close error handler
	if s.errorHandler != nil {
		s.errorHandler.Close()
	}
}
