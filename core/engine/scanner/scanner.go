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
}

// NewScanner creates a new Scanner instance
func NewScanner(opts *ScannerOpts, urls []string) *Scanner {
	s := &Scanner{
		scannerOpts: opts,
		urls:        urls,
	}
	s.progressBarEnabled.Store(!opts.DisableProgressBar)
	return s
}

// Run runs the scanner..
func (s *Scanner) Run() error {
	defer s.Close()

	GB403Logger.Info().Msgf("Initializing scanner with %d URLs", len(s.urls))

	for _, url := range s.urls {
		parsedURL, err := rawurlparser.RawURLParse(url)
		if err != nil {
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

	fmt.Println()
	GB403Logger.Success().Msgf("Findings saved to %s\n\n",
		s.scannerOpts.ResultsDBFile)
	GB403ErrorHandler.GetErrorHandler().PrintErrorStats()
	return nil
}

func (s *Scanner) scanURL(url string) error {
	resultCount := s.RunAllBypasses(url)

	if resultCount > 0 {
		resultsFile := s.scannerOpts.ResultsDBFile

		fmt.Println()
		if err := PrintResultsTableFromDB(url, s.scannerOpts.BypassModule); err != nil {
			GB403Logger.Error().Msgf("Failed to display results: %v\n", err)
		} else {
			fmt.Println()
			GB403Logger.Success().Msgf("%d findings saved to %s\n\n",
				resultCount, resultsFile)
		}
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
