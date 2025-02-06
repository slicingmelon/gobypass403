package scanner

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/slicingmelon/go-bypass-403/internal/engine/recon"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
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
	Proxy                   string
	EnableHTTP2             bool
	SpoofHeader             string
	SpoofIP                 string
	FollowRedirects         bool
	ResponseBodyPreviewSize int
	ReconCache              *recon.ReconCache
}

// Scanner represents the main scanner structure, perhaps the highest level in the hierarchy of the tool
type Scanner struct {
	config       *ScannerOpts
	urls         []string
	errorHandler *GB403ErrorHandler.ErrorHandler
}

// NewScanner creates a new Scanner instance
func NewScanner(opts *ScannerOpts, urls []string) *Scanner {
	// Initialize bypass modules first
	InitializeBypassModules()

	return &Scanner{
		config:       opts,
		urls:         urls,
		errorHandler: GB403ErrorHandler.NewErrorHandler(32),
	}
}

// Run runs the scanner..
func (s *Scanner) Run() error {
	defer s.Close()

	GB403Logger.Info().Msgf("Initializing scanner with %d URLs", len(s.urls))

	for _, url := range s.urls {
		if err := s.scanURL(url); err != nil {
			GB403Logger.Error().Msgf("Error scanning %s: %v", url, err)
			if handleErr := s.errorHandler.HandleError(err, GB403ErrorHandler.ErrorContext{
				TargetURL:    []byte(url),
				ErrorSource:  []byte("Scanner.Run"),
				BypassModule: []byte(s.config.BypassModule),
			}); handleErr != nil {
				GB403Logger.Error().Msgf("Error handling error: %v", handleErr)
			}
			continue
		}
	}

	// print error stats
	fmt.Println()
	s.errorHandler.PrintErrorStats()

	return nil
}

func (s *Scanner) scanURL(url string) error {
	resultsChannel := s.RunAllBypasses(url)
	var allFindings []*Result

	// Process results as they come in
	for result := range resultsChannel {
		if result != nil {
			GB403Logger.Debug().Msgf("Processing results for bypass module: %s, status: %d", result.BypassModule, result.StatusCode)
			allFindings = append(allFindings, result)
		}

	}

	// If we have any findings, sort and save them
	if len(allFindings) > 0 {
		// Sort findings by status code and then by module
		sort.Slice(allFindings, func(i, j int) bool {
			if allFindings[i].StatusCode != allFindings[j].StatusCode {
				return allFindings[i].StatusCode < allFindings[j].StatusCode
			}
			return allFindings[i].BypassModule < allFindings[j].BypassModule
		})

		// Save findings first
		outputFile := filepath.Join(s.config.OutDir, "findings.json")
		if err := AppendResultsToJSON(outputFile, url, s.config.BypassModule, allFindings); err != nil {
			GB403Logger.Error().Msgf("Failed to save findings for %s: %v", url, err)
		}

		// Print results only once
		fmt.Println()
		PrintResultsTable(url, allFindings)

		fmt.Println()
		GB403Logger.Success().Msgf("Results saved to %s\n\n", outputFile)
	}

	return nil
}

// Close the scanner instance
func (s *Scanner) Close() {
	// Close error handler
	if s.errorHandler != nil {
		s.errorHandler.Reset()
	}
}
