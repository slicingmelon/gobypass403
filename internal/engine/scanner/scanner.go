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

	for _, url := range s.urls {
		if err := s.scanURL(url); err != nil {
			GB403Logger.Error().Msgf("Error scanning %s: %v", url, err)
			if handleErr := GB403ErrorHandler.GetErrorHandler().HandleError(err, GB403ErrorHandler.ErrorContext{
				TargetURL:    []byte(url),
				ErrorSource:  []byte("Scanner.Run"),
				BypassModule: []byte(s.scannerOpts.BypassModule),
			}); handleErr != nil {
				GB403Logger.Error().Msgf("Error handling error: %v", handleErr)
			}
			continue
		}
	}

	// print error stats
	fmt.Println()
	GB403ErrorHandler.GetErrorHandler().PrintErrorStats()

	return nil
}

func (s *Scanner) scanURL(url string) error {
	resultsChannel := s.RunAllBypasses(url)
	var allFindings []*Result

	// Process results as they come in
	for result := range resultsChannel {
		if result != nil {
			//GB403Logger.Debug().Msgf("Processing results for bypass module: %s, status: %d\n", result.BypassModule, result.StatusCode)
			allFindings = append(allFindings, result)
		}
	}

	// If we have any findings, sort and save them
	if len(allFindings) > 0 {
		// Load from JSON and print
		outputFile := filepath.Join(s.scannerOpts.OutDir, "findings.json")
		fmt.Println()
		if err := PrintResultsFromJSON(outputFile, url, s.scannerOpts.BypassModule); err != nil {
			GB403Logger.Error().Msgf("Failed to print results from JSON: %v\n", err)
		} else {
			fmt.Println()
			GB403Logger.Success().Msgf("Results saved to %s\n\n", outputFile)
		}
	}

	return nil
}

// Close the scanner instance
func (s *Scanner) Close() {
	// Close error handler
	//
}
