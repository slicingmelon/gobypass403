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

func InitResultsFile(path string) {
	resultsFile.Store(path)
}

func GetResultsFile() string {
	return resultsFile.Load().(string)
}

// NewScanner creates a new Scanner instance
func NewScanner(opts *ScannerOpts, urls []string) *Scanner {
	InitResultsFile(filepath.Join(opts.OutDir, "findings.json"))

	// Initialize bypass modules first
	InitializeBypassModules()

	s := &Scanner{
		scannerOpts: opts,
		urls:        urls,
	}
	s.progressBarEnabled.Store(!opts.DisableProgressBar) // Set once
	return s
}

// Run runs the scanner..
func (s *Scanner) Run() error {
	defer s.Close()

	// Normal scanning mode
	GB403Logger.Info().Msgf("Initializing scanner with %d URLs", len(s.urls))

	for _, url := range s.urls {
		parsedURL, err := rawurlparser.RawURLParse(url)
		if err != nil {
			host := ""
			if parsedURL != nil {
				host = parsedURL.BaseURL()
			}

			if handleErr := GB403ErrorHandler.GetErrorHandler().HandleError(err, GB403ErrorHandler.ErrorContext{
				Host:         []byte(host),
				ErrorSource:  []byte("Scanner.Run"),
				BypassModule: []byte(s.scannerOpts.BypassModule),
			}); handleErr != nil {
				GB403Logger.Error().Msgf("Error handling error: %v", handleErr)
			}
			continue
		}

		if err := s.scanURL(url); err != nil {
			// Handle scan error
			host := parsedURL.BaseURL() // We know parsedURL is valid here
			if handleErr := GB403ErrorHandler.GetErrorHandler().HandleError(err, GB403ErrorHandler.ErrorContext{
				Host:         []byte(host),
				ErrorSource:  []byte("Scanner.Run"),
				BypassModule: []byte(s.scannerOpts.BypassModule),
			}); handleErr != nil {
				GB403Logger.Error().Msgf("Error handling error: %v", handleErr)
			}
		}
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
		resultsFile := GetResultsFile()

		fmt.Println()
		if err := PrintResultsTableFromJsonL(resultsFile, url, s.scannerOpts.BypassModule); err != nil {
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
