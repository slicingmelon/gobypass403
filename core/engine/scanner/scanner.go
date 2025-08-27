/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package scanner

import (
	"fmt"
	"sync/atomic"

	"github.com/slicingmelon/go-rawurlparser"
	"github.com/slicingmelon/gobypass403/core/engine/recon"
	GB403ErrorHandler "github.com/slicingmelon/gobypass403/core/utils/error"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

type ScannerOpts struct {
	Timeout                   int
	ConcurrentRequests        int
	MatchStatusCodes          []int
	MatchContentTypeBytes     [][]byte
	MinContentLength          int
	MaxContentLength          int
	Debug                     bool
	Verbose                   bool
	BypassModule              string
	OutDir                    string
	ResultsDBFile             string
	RequestDelay              int
	MaxRetries                int
	RetryDelay                int
	MaxConsecutiveFailedReqs  int
	AutoThrottle              bool
	Proxy                     string
	EnableHTTP2               bool
	SpoofHeader               string
	SpoofIP                   string
	CustomHTTPHeaders         []string // Custom HTTP headers in "Name: Value" format
	FollowRedirects           bool
	ResponseBodyPreviewSize   int
	DisableStreamResponseBody bool
	DisableProgressBar        bool
	ResendRequest             string
	EnableTUI                 bool
	ReconCache                *recon.ReconCache
}

// Scanner represents the main scanner structure, perhaps the highest level in the hierarchy of the tool
type Scanner struct {
	scannerOpts        *ScannerOpts
	urls               []string
	progressBarEnabled atomic.Bool
	tuiController      *TUIController
}

// NewScanner creates a new Scanner instance
func NewScanner(opts *ScannerOpts, urls []string) *Scanner {
	s := &Scanner{
		scannerOpts: opts,
		urls:        urls,
	}
	s.progressBarEnabled.Store(!opts.DisableProgressBar)

	// Initialize TUI controller only if TUI is enabled
	if opts.EnableTUI {
		s.tuiController = NewTUIController(urls)
	}

	return s
}

// Run runs the scanner..
func (s *Scanner) Run() error {
	defer s.Close()

	if s.scannerOpts.EnableTUI {
		// TUI mode
		return s.runWithTUI()
	} else {
		// Standard mode with progress bars
		return s.runStandard()
	}
}

// runWithTUI runs the scanner with TUI interface
func (s *Scanner) runWithTUI() error {
	// Start scanning in background
	go func() {
		for _, url := range s.urls {
			parsedURL, err := rawurlparser.RawURLParse(url)
			if err != nil {
				// Send error to TUI
				s.tuiController.SendProgress(url, "error", 0, 0, true, err.Error())

				GB403ErrorHandler.GetErrorHandler().HandleErrorAndContinue(err, GB403ErrorHandler.ErrorContext{
					Host:         parsedURL.BaseURL(),
					ErrorSource:  "Scanner.Run.URLParse",
					BypassModule: s.scannerOpts.BypassModule,
				})
				continue
			}

			_ = s.scanURL(url)
		}
	}()

	// Start TUI (blocks until user quits)
	return s.tuiController.Start()
}

// runStandard runs the scanner with standard output and progress bars
func (s *Scanner) runStandard() error {
	GB403Logger.Info().Msgf("Initializing scanner with %d URLs", len(s.urls))

	for _, url := range s.urls {
		parsedURL, err := rawurlparser.RawURLParse(url)
		if err != nil {
			GB403ErrorHandler.GetErrorHandler().HandleErrorAndContinue(err, GB403ErrorHandler.ErrorContext{
				Host:         parsedURL.BaseURL(),
				ErrorSource:  "Scanner.Run.URLParse",
				BypassModule: s.scannerOpts.BypassModule,
			})
			continue
		}

		_ = s.scanURL(url)
	}

	// Print completion summary
	GB403Logger.Success().Msgf("Findings saved to %s\n", s.scannerOpts.ResultsDBFile)
	GB403ErrorHandler.GetErrorHandler().PrintErrorStats()

	return nil
}

func (s *Scanner) scanURL(url string) error {
	if s.scannerOpts.EnableTUI {
		// TUI mode - pass TUI controller
		_ = s.RunAllBypassesWithTUI(url, s.tuiController)
	} else {
		// Standard mode - no TUI controller
		totalFindings := s.RunAllBypasses(url)

		// Print results table immediately after scanning this URL
		if err := PrintResultsTableFromDB(url, s.scannerOpts.BypassModule); err != nil {
			GB403Logger.Error().Msgf("Failed to display results: %v\n", err)
		}
		fmt.Println()

		// Print summary for this URL
		GB403Logger.Success().Msgf("Found %d results for %s", totalFindings, url)
		fmt.Println()
	}
	return nil
}

// Close the scanner instance
func (s *Scanner) Close() {
	// Reset error handler instance (this will also close ristretto caches)
	GB403ErrorHandler.ResetInstance()

	// Cleanup sqlite db (findings db)
	CleanupFindingsDB()
}
