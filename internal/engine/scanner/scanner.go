package scanner

import (
	"fmt"
	"path/filepath"

	"github.com/slicingmelon/go-bypass-403/internal/engine/recon"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
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
	ResendRequest             string
	ReconCache                *recon.ReconCache
}

// Scanner represents the main scanner structure, perhaps the highest level in the hierarchy of the tool
type Scanner struct {
	scannerOpts *ScannerOpts
	urls        []string
}

// NewScanner creates a new Scanner instance
func NewScanner(opts *ScannerOpts, urls []string) *Scanner {
	// Initialize bypass modules first
	InitializeBypassModules()

	return &Scanner{
		scannerOpts: opts,
		urls:        urls,
	}
}

// Run runs the scanner..
func (s *Scanner) Run() error {
	defer s.Close()

	// Normal scanning mode
	GB403Logger.Info().Msgf("Initializing scanner with %d URLs", len(s.urls))

	outputFile := filepath.Join(s.scannerOpts.OutDir, "findings.json")

	for _, url := range s.urls {
		if err := s.scanURL(url); err != nil {
			GB403Logger.Error().Msgf("Error scanning %s: %v", url, err)
			if handleErr := GB403ErrorHandler.GetErrorHandler().HandleError(err, GB403ErrorHandler.ErrorContext{
				TargetURL:    []byte(url),
				ErrorSource:  []byte("Scanner.Run"),
				BypassModule: []byte(s.scannerOpts.BypassModule),
			}); handleErr != nil {
				GB403Logger.Error().Msgf("Error handling error: %v\n", handleErr)
			}
			continue
		}
	}

	// Close the JSON array after all URLs are processed
	if err := CloseJsonArray(outputFile); err != nil {
		GB403Logger.Error().Msgf("Failed to close JSON array: %v\n", err)
	}

	// print error stats
	fmt.Println()
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
		outputFile := filepath.Join(s.scannerOpts.OutDir, "findings.json")

		fmt.Println()
		if err := PrintResultsTableFromJsonL(outputFile, url, s.scannerOpts.BypassModule); err != nil {
			GB403Logger.Error().Msgf("Failed to display results: %v\n", err)
		} else {
			fmt.Println()
			GB403Logger.Success().Msgf("%d findings saved to %s\n\n",
				resultCount, outputFile)
		}
	}

	return nil
}

// Close the scanner instance
func (s *Scanner) Close() {
	// Close error handler
	//
}
