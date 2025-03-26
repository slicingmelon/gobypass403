package scanner

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/bytesutil"
	"github.com/pterm/pterm"
	"github.com/slicingmelon/go-rawurlparser"
)

// ProgressBar manages a combined spinner and progress bar display
type ProgressBar struct {
	multiprinter *pterm.MultiPrinter
	spinner      *pterm.SpinnerPrinter
	progressbar  *pterm.ProgressbarPrinter
	mu           sync.RWMutex
	bypassModule string
	targetURL    string
	truncatedURL string
	totalJobs    int
	totalWorkers int

	// optimiz
	coloredModule string
	coloredURL    string
}

// NewProgressBar creates a new progress display for a bypass module
func NewProgressBar(bypassModule string, targetURL string, totalJobs int, totalWorkers int) *ProgressBar {
	//termWidth := pterm.GetTerminalWidth()

	// Simple URL truncation - consistent for all displays
	truncatedURL := simpleTruncateURL(targetURL)

	// Fixed width progress bar for better terminal compatibility
	progressBarWidth := 80

	multi := &pterm.MultiPrinter{
		Writer:      os.Stdout,
		UpdateDelay: time.Millisecond * 200,
	}

	spinnerPrinter := &pterm.SpinnerPrinter{
		Sequence:            []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		Style:               &pterm.ThemeDefault.SpinnerStyle,
		Delay:               time.Millisecond * 200,
		MessageStyle:        &pterm.ThemeDefault.SpinnerTextStyle,
		SuccessPrinter:      &pterm.Success,
		FailPrinter:         &pterm.Error,
		WarningPrinter:      &pterm.Warning,
		ShowTimer:           true,
		TimerRoundingFactor: time.Second,
		TimerStyle:          &pterm.ThemeDefault.TimerStyle,
		Writer:              multi.NewWriter(),
	}

	progressPrinter := &pterm.ProgressbarPrinter{
		Total:                     totalJobs,
		BarCharacter:              "█",
		LastCharacter:             "█",
		ElapsedTimeRoundingFactor: time.Second,
		BarStyle:                  &pterm.ThemeDefault.ProgressbarBarStyle,
		TitleStyle:                &pterm.ThemeDefault.ProgressbarTitleStyle,
		ShowTitle:                 true,
		ShowCount:                 true,
		ShowPercentage:            true,
		ShowElapsedTime:           true,
		BarFiller:                 pterm.Gray("█"),
		MaxWidth:                  progressBarWidth,
		Writer:                    multi.NewWriter(),
	}

	coloredModule := pterm.LightCyan(bypassModule)
	coloredURL := pterm.FgYellow.Sprint(truncatedURL)

	return &ProgressBar{
		multiprinter:  multi,
		spinner:       spinnerPrinter,
		progressbar:   progressPrinter,
		mu:            sync.RWMutex{},
		bypassModule:  bypassModule,
		targetURL:     targetURL,
		truncatedURL:  truncatedURL,
		totalJobs:     totalJobs,
		totalWorkers:  totalWorkers,
		coloredModule: coloredModule,
		coloredURL:    coloredURL,
	}
}

func simpleTruncateURL(url string) string {
	// Use the rawurlparser to get just scheme://host
	if parsedURL, err := rawurlparser.RawURLParse(url); err == nil {
		// Return scheme://host... format
		return fmt.Sprintf("%s://%s ...", parsedURL.Scheme, parsedURL.Host)
	}
	// Simple fallback if parsing completely fails
	return url
}

// Increment advances the progress bar by one step
func (pb *ProgressBar) Increment() {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	if pb.progressbar != nil {
		pb.progressbar.Add(1)

		updatedBar := *pb.progressbar
		updatedBar.Title = pb.bypassModule
		*pb.progressbar = updatedBar

		// Ensure we don't exceed 100%
		if pb.progressbar.Current > pb.progressbar.Total {
			pb.progressbar.Current = pb.progressbar.Total
		}
	}
}

func (pb *ProgressBar) UpdateSpinnerText(
	activeWorkers int64,
	completedTasks uint64,
	submittedTasks uint64,
	currentRate uint64,
	avgRate uint64,
) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	var spinnerBuilder strings.Builder
	var titleBuilder strings.Builder

	// Build spinner text
	spinnerBuilder.WriteString(pb.coloredModule)
	spinnerBuilder.WriteString(" | Workers [")
	spinnerBuilder.WriteString(bytesutil.Itoa(int(activeWorkers)))
	spinnerBuilder.WriteString("/")
	spinnerBuilder.WriteString(bytesutil.Itoa(pb.totalWorkers))
	spinnerBuilder.WriteString("] | Rate [")
	spinnerBuilder.WriteString(bytesutil.Itoa(int(currentRate)))
	spinnerBuilder.WriteString(" req/s] Avg [")
	spinnerBuilder.WriteString(bytesutil.Itoa(int(avgRate)))
	spinnerBuilder.WriteString(" req/s]")
	pb.spinner.UpdateText(spinnerBuilder.String())

	// Build progress bar title
	if pb.progressbar != nil {
		titleBuilder.WriteString(pb.coloredModule)
		titleBuilder.WriteString(" | ")
		titleBuilder.WriteString(pb.coloredURL)
		pb.progressbar.UpdateTitle(titleBuilder.String())
	}
}

func (pb *ProgressBar) SpinnerSuccess(
	completedTasks uint64,
	submittedTasks uint64,
	avgRate uint64,
	peakRate uint64,
) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	// // Ensure progress bar is 100% complete
	// if pb.progressbar != nil && pb.progressbar.Current < pb.progressbar.Total {
	// 	pb.progressbar.Current = pb.progressbar.Total
	// }

	// 	// Ensure progress bar is 100% complete
	// 	if pb.progressbar != nil && pb.progressbar.Current < pb.progressbar.Total {
	// 		pb.progressbar.Current = pb.progressbar.Total
	// 	}

	var spinnerBuilder strings.Builder
	var titleBuilder strings.Builder

	// Build success spinner message showing module and stats
	spinnerBuilder.WriteString(pb.coloredModule)
	spinnerBuilder.WriteString(" | Workers [")
	spinnerBuilder.WriteString(bytesutil.Itoa(pb.totalWorkers))
	spinnerBuilder.WriteString("/")
	spinnerBuilder.WriteString(bytesutil.Itoa(pb.totalWorkers))
	spinnerBuilder.WriteString("] | Rate [")
	spinnerBuilder.WriteString(bytesutil.Itoa(int(avgRate)))
	spinnerBuilder.WriteString(" req/s] Peak [")
	spinnerBuilder.WriteString(bytesutil.Itoa(int(peakRate)))
	spinnerBuilder.WriteString(" req/s]")

	// Update progress bar title to remain with module and URL
	if pb.progressbar != nil {
		titleBuilder.WriteString(pb.coloredModule)
		titleBuilder.WriteString(" | ")
		titleBuilder.WriteString(pb.coloredURL)
		pb.progressbar.UpdateTitle(titleBuilder.String())
	}

	// Ensure a final update of the progress bar title if needed
	if pb.progressbar != nil {
		pb.progressbar.UpdateTitle(pb.progressbar.Title)
	}

	// Show success spinner message
	pb.spinner.Success(spinnerBuilder.String())
}

func (pb *ProgressBar) SpinnerFailed(
	completedTasks uint64,
	totalTasks uint64,
	avgRate uint64,
	peakRate uint64,
) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	// DO NOT force progress bar to 100% like in SpinnerSuccess
	// Keep the actual progress at cancellation time

	var spinnerBuilder strings.Builder
	var titleBuilder strings.Builder

	// Build failure spinner message showing module and stats
	spinnerBuilder.WriteString(pb.coloredModule)
	spinnerBuilder.WriteString(" | Workers [")
	spinnerBuilder.WriteString(bytesutil.Itoa(pb.totalWorkers))
	spinnerBuilder.WriteString("/")
	spinnerBuilder.WriteString(bytesutil.Itoa(pb.totalWorkers))
	spinnerBuilder.WriteString("] | Rate [")
	spinnerBuilder.WriteString(bytesutil.Itoa(int(avgRate)))
	spinnerBuilder.WriteString(" req/s] Peak [")
	spinnerBuilder.WriteString(bytesutil.Itoa(int(peakRate)))
	spinnerBuilder.WriteString(" req/s]")

	// Update progress bar title to remain with module and URL
	if pb.progressbar != nil {
		titleBuilder.WriteString(pb.coloredModule)
		titleBuilder.WriteString(" | ")
		titleBuilder.WriteString(pb.coloredURL)
		pb.progressbar.UpdateTitle(titleBuilder.String())
	}

	// Show failed spinner message
	pb.spinner.Fail(spinnerBuilder.String())
}

// UpdateProgressbarTitle updates the progress bar title
func (pb *ProgressBar) UpdateProgressbarTitle(title string) {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	pb.progressbar.UpdateTitle(title)
}

// Start initializes the progressbar
func (pb *ProgressBar) Start() {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	var spinnerBuilder strings.Builder
	var titleBuilder strings.Builder

	// Build initial spinner text showing module and initial stats
	spinnerBuilder.WriteString(pb.coloredModule)
	spinnerBuilder.WriteString(" | Workers [0/")
	spinnerBuilder.WriteString(bytesutil.Itoa(pb.totalWorkers))
	spinnerBuilder.WriteString("] | Rate [0 req/s] Avg [0 req/s]")
	initialSpinnerText := spinnerBuilder.String()

	// Build initial progress bar title showing module and URL
	titleBuilder.WriteString(pb.coloredModule)
	titleBuilder.WriteString(" | ")
	titleBuilder.WriteString(pb.coloredURL)
	progressTitle := titleBuilder.String()

	// Start multiprinter first
	if pb.multiprinter != nil {
		pb.multiprinter.Start()
	}

	// Start spinner with a slight delay for terminal readiness
	if pb.spinner != nil {
		started, _ := pb.spinner.Start(initialSpinnerText)
		pb.spinner = started
	}

	// Now start the progress bar
	if pb.progressbar != nil {
		updatedBar := *pb.progressbar
		updatedBar.Title = progressTitle
		started, _ := updatedBar.Start()
		pb.progressbar = started
	}
}

// Stop terminates the progress display
func (pb *ProgressBar) Stop() {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	// First ensure the spinner is stopped properly
	if pb.spinner != nil {
		pb.spinner.Stop()
	}

	// Then stop progressbar
	if pb.progressbar != nil {
		// Ensure progress bar is at 100% before stopping
		// if pb.progressbar.Current < pb.progressbar.Total {
		// 	pb.progressbar.Current = pb.progressbar.Total
		// }

		// Force a final update before stopping
		pb.progressbar.UpdateTitle(pb.progressbar.Title)

		// Now stop
		pb.progressbar.Stop()
	}

	// Finally stop multiprinter
	if pb.multiprinter != nil {
		pb.multiprinter.Stop()
	}

	// Print newlines to ensure proper spacing
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout)
}
