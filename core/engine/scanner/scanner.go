/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package scanner

import (
	"sync/atomic"

	"github.com/slicingmelon/go-rawurlparser"
	"github.com/slicingmelon/gobypass403/core/engine/recon"
	GB403ErrorHandler "github.com/slicingmelon/gobypass403/core/utils/error"
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

	// Initialize TUI controller with target URLs
	s.tuiController = NewTUIController(urls)

	return s
}

// Run runs the scanner..
func (s *Scanner) Run() error {
	defer s.Close()

	// Comment out logger call - interferes with TUI display
	// GB403Logger.Info().Msgf("Initializing scanner with %d URLs", len(s.urls))

	// Start scanning in background
	go func() {
		// Don't auto-shutdown TUI - let user decide when to quit
		// defer s.tuiController.Shutdown()

		for _, url := range s.urls {
			parsedURL, err := rawurlparser.RawURLParse(url)
			if err != nil {
				// Send error to TUI
				s.tuiController.SendProgress(url, "error", 0, 0, true, err.Error())

				// Keep one error handling as reference example
				GB403ErrorHandler.GetErrorHandler().HandleErrorAndContinue(err, GB403ErrorHandler.ErrorContext{
					Host:         parsedURL.BaseURL(),
					ErrorSource:  "Scanner.Run.URLParse",
					BypassModule: s.scannerOpts.BypassModule,
				})
				continue
			}

			// Just scan and continue on error - no need for nested error handling
			_ = s.scanURL(url)
		}

		// All scanning complete - don't print to stdout as it interferes with TUI
		// GB403Logger.Success().Msgf("Findings saved to %s\n", s.scannerOpts.ResultsDBFile)
		// GB403ErrorHandler.GetErrorHandler().PrintErrorStats()

		// Could send a completion message to TUI instead if needed
		// tuiController.SendProgress("SCAN_COMPLETE", "All targets completed", 0, 0, true, "")
	}()

	// Start TUI (blocks until user quits)
	return s.tuiController.Start()
}

func (s *Scanner) scanURL(url string) error {
	// TUI will handle all display - just run the bypass modules
	_ = s.RunAllBypasses(url, s.tuiController)
	return nil
}

// Close the scanner instance
func (s *Scanner) Close() {
	// Reset error handler instance (this will also close ristretto caches)
	GB403ErrorHandler.ResetInstance()

	// Cleanup sqlite db (findings db)
	CleanupFindingsDB()
}
