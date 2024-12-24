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
	TraceRequests           bool
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
	logger       GB403Logger.ILogger
	progress     *ProgressCounter
}

// NewScanner creates a new Scanner instance
func NewScanner(opts *ScannerOpts, urls []string, logger GB403Logger.ILogger) *Scanner {
	// Initialize bypass modules first
	InitializeBypassModules(logger)

	errorHandler := GB403ErrorHandler.NewErrorHandler(32)
	progress := NewProgressCounter()

	return &Scanner{
		config:       opts,
		urls:         urls,
		logger:       logger,
		errorHandler: errorHandler,
		progress:     progress,
	}
}

func (s *Scanner) Run() error {
	defer s.Close()

	s.logger.PrintYellow("Initializing scanner with %d URLs", len(s.urls))

	// Start progress counter here instead
	s.progress.Start()
	defer s.progress.Stop() // Move Stop here to ensure it runs after all URLs are processed

	for _, url := range s.urls {
		if err := s.scanURL(url); err != nil {
			s.logger.LogError("Error scanning %s: %v", url, err)
			if handleErr := s.errorHandler.HandleError(err, GB403ErrorHandler.ErrorContext{
				TargetURL:    []byte(url),
				ErrorSource:  []byte("Scanner.Run"),
				BypassModule: []byte(s.config.BypassModule),
			}); handleErr != nil {
				s.logger.LogError("Error handling error: %v", handleErr)
			}
			continue
		}
	}

	// print error stats
	s.errorHandler.PrintErrorStats()

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

	// Sort findings by module and status code for better presentation
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].BypassModule != findings[j].BypassModule {
			return findings[i].BypassModule < findings[j].BypassModule
		}
		return findings[i].StatusCode < findings[j].StatusCode
	})

	// Then process and display them
	if len(findings) > 0 {
		fmt.Println()
		fmt.Println()
		PrintTableHeader(url)
		for _, re := range findings {
			PrintTableRow(re)
		}
	}

	fmt.Println()

	outputFile := filepath.Join(s.config.OutDir, "findings.json")
	if err := AppendResultsToJSON(outputFile, url, s.config.BypassModule, findings); err != nil {
		if handleErr := s.errorHandler.HandleError(err, GB403ErrorHandler.ErrorContext{
			TargetURL:    []byte(url),
			ErrorSource:  []byte("Scanner.scanURL"),
			BypassModule: []byte(s.config.BypassModule),
		}); handleErr != nil {
			return fmt.Errorf("failed to handle error (%v) while processing error: %w", handleErr, err)
		}
		return fmt.Errorf("failed to append results to JSON: %w", err)
	}

	// Add notification about where results were saved
	fmt.Println()
	s.logger.PrintOrange("Results saved to: %s\n", outputFile)

	return nil
}

func (s *Scanner) Close() {
	// Close error handler
	if s.errorHandler != nil {
		s.errorHandler.Reset()
	}
}
