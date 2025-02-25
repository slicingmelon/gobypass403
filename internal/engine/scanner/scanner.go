package scanner

import (
	"fmt"
	"path/filepath"
	"sync/atomic"

	"github.com/slicingmelon/go-bypass-403/internal/engine/recon"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/slicingmelon/go-rawurlparser"
)

type ScannerOpts struct {
	Timeout                   int
	Threads                   int
	MatchStatusCodes          []int
	Debug                     bool
	Verbose                   bool
	BypassModule              string
	OutDir                    string
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

func InitResultsDBFile(path string) {
	resultsDBFile.Store(path)
}

// GetDBPath returns the current database path
func GetResultsDBFile() string {
	return resultsDBFile.Load().(string)
}

// NewScanner creates a new Scanner instance
func NewScanner(opts *ScannerOpts, urls []string) *Scanner {
	// Initialize database path
	dbPath := filepath.Join(opts.OutDir, "results.db")
	InitResultsDBFile(dbPath)

	// Initialize bypass modules first
	InitializeBypassModules()

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

	GB403ErrorHandler.GetErrorHandler().PrintErrorStats()
	return nil
}

func (s *Scanner) scanURL(url string) error {
	resultsChannel := s.RunAllBypasses(url)

	var resultCount int
	for result := range resultsChannel {
		if result != nil {
			resultCount++
		}
	}

	if resultCount > 0 {
		resultsFile := GetResultsDBFile()

		fmt.Println()
		// if err := PrintResultsTableFromJsonL(resultsFile, url, s.scannerOpts.BypassModule); err != nil {
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
	// Close error handler
	//
}
