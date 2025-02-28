package scanner

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/bytesutil"
	"github.com/pterm/pterm"
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
}

// NewProgressBar creates a new progress display for a bypass module
func NewProgressBar(bypassModule string, targetURL string, totalJobs int, totalWorkers int) *ProgressBar {
	termWidth := pterm.GetTerminalWidth()

	// Simple URL truncation - consistent for all displays
	truncatedURL := simpleTruncateURL(targetURL, 40)

	// Fixed width progress bar that works well in most terminals
	progressBarWidth := min(90, termWidth-10)

	// // Second use: calculate progress bar width based on truncated URL
	// desiredWidth := len(truncatedURL) + len("Complete: ") + 10
	// maxWidth := min(desiredWidth, termWidth)
	// if maxWidth < 80 {
	// 	maxWidth = min(80, termWidth)
	// }

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

	return &ProgressBar{
		multiprinter: multi,
		spinner:      spinnerPrinter,
		progressbar:  progressPrinter,
		mu:           sync.RWMutex{},
		bypassModule: bypassModule,
		targetURL:    targetURL,
		truncatedURL: truncatedURL,
		totalJobs:    totalJobs,
		totalWorkers: totalWorkers,
	}
}

func simpleTruncateURL(url string, maxLength int) string {
	if len(url) <= maxLength {
		return url
	}

	// Extract scheme
	scheme := ""
	if strings.HasPrefix(url, "http://") {
		scheme = "http://"
	} else if strings.HasPrefix(url, "https://") {
		scheme = "https://"
	}

	urlBody := strings.TrimPrefix(url, scheme)

	// We want to keep the domain part at minimum
	parts := strings.SplitN(urlBody, "/", 2)
	domain := parts[0]

	// If domain is already too long, truncate it
	if len(domain) > maxLength-5 {
		return scheme + domain[:maxLength-5] + "..."
	}

	// If there's no path, just return domain
	if len(parts) < 2 || parts[1] == "" {
		return scheme + domain
	}

	// Calculate how much space we have for the path
	remainingSpace := maxLength - len(scheme) - len(domain) - 4 // -4 for "/..."

	// If not enough space, just show domain
	if remainingSpace < 5 {
		return scheme + domain + "/..."
	}

	return scheme + domain + "/..." + parts[1][max(0, len(parts[1])-remainingSpace):]
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

// UpdateSpinnerText
func (pb *ProgressBar) UpdateSpinnerText(
	activeWorkers int64,
	completedTasks uint64,
	submittedTasks uint64,
	currentRate uint64,
	avgRate uint64,
) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	var spinnerBuf, titleBuf strings.Builder

	// Spinner text
	spinnerBuf.WriteString(pterm.LightCyan(pb.bypassModule))
	spinnerBuf.WriteString(" | Scanning ")
	spinnerBuf.WriteString(pterm.FgYellow.Sprint(pb.truncatedURL))
	pb.spinner.UpdateText(spinnerBuf.String())

	// Progress bar title
	if pb.progressbar != nil {
		titleBuf.Grow(len(pb.bypassModule) + 100) // approximate size for stats
		titleBuf.WriteString(pterm.LightCyan(pb.bypassModule))
		titleBuf.WriteString(" | Workers [")
		titleBuf.WriteString(bytesutil.Itoa(int(activeWorkers)))
		titleBuf.WriteString("/")
		titleBuf.WriteString(bytesutil.Itoa(pb.totalWorkers))
		titleBuf.WriteString("] | Rate [")
		titleBuf.WriteString(bytesutil.Itoa(int(currentRate)))
		titleBuf.WriteString(" req/s] Avg [")
		titleBuf.WriteString(bytesutil.Itoa(int(avgRate)))
		titleBuf.WriteString(" req/s]")

		pb.progressbar.UpdateTitle(titleBuf.String())
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

	// Success message with truncated URL
	var spinnerBuf strings.Builder
	spinnerBuf.WriteString(pterm.White("Complete"))
	spinnerBuf.WriteString(": ")
	spinnerBuf.WriteString(pterm.FgYellow.Sprint(pb.truncatedURL))
	pb.spinner.Success(spinnerBuf.String())

	// Update final progressbar title with peak rate
	if pb.progressbar != nil {
		var titleBuf strings.Builder
		titleBuf.WriteString(pterm.LightCyan(pb.bypassModule))
		titleBuf.WriteString(" | Workers [")
		titleBuf.WriteString(bytesutil.Itoa(pb.totalWorkers)) // Show total workers instead of active
		titleBuf.WriteString("/")
		titleBuf.WriteString(bytesutil.Itoa(pb.totalWorkers))
		titleBuf.WriteString("] | Rate [")
		titleBuf.WriteString(bytesutil.Itoa(int(avgRate)))
		titleBuf.WriteString(" req/s] Peak [") // Add peak rate
		titleBuf.WriteString(bytesutil.Itoa(int(peakRate)))
		titleBuf.WriteString(" req/s]")

		pb.progressbar.UpdateTitle(titleBuf.String())
	}
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

	// Pre-allocate builders
	var spinnerBuf strings.Builder
	var titleBuf strings.Builder

	// Build initial spinner text - using truncatedURL for consistency
	spinnerBuf.Grow(len(pb.bypassModule) + len(pb.truncatedURL) + 20) // approximate size
	spinnerBuf.WriteString(pterm.LightCyan(pb.bypassModule))
	spinnerBuf.WriteString(" | Scanning ")
	spinnerBuf.WriteString(pterm.FgYellow.Sprint(pb.truncatedURL))
	initialSpinnerText := spinnerBuf.String()

	// Build initial progressbar title
	titleBuf.Grow(len(pb.bypassModule) + 50) // approximate size for stats
	titleBuf.WriteString(pterm.LightCyan(pb.bypassModule))
	titleBuf.WriteString(" | Workers [0/")
	titleBuf.WriteString(bytesutil.Itoa(pb.totalWorkers))
	titleBuf.WriteString("] | Rate [0 req/s] Avg [0 req/s]")
	progressTitle := titleBuf.String()

	// Start multiprinter first
	if pb.multiprinter != nil {
		pb.multiprinter.Start()
	}

	// Start spinner with small delay to ensure terminal is ready
	if pb.spinner != nil {
		started, _ := pb.spinner.Start(initialSpinnerText)
		pb.spinner = started
	}

	// Add a tiny sleep to prevent visual glitches
	time.Sleep(50 * time.Millisecond)

	// Now start progressbar
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
		// Small delay to let terminal update
		time.Sleep(50 * time.Millisecond)
	}

	// Then stop progressbar
	if pb.progressbar != nil {
		// Ensure progress bar is at 100% before stopping
		if pb.progressbar.Current < pb.progressbar.Total {
			pb.progressbar.Current = pb.progressbar.Total
		}

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

// This new method should be called before the spinner success to make sure
// the progress bar and worker counts are properly synchronized
func (pb *ProgressBar) PrepareForCompletion(
	peakRate uint64,
	avgRate uint64,
) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	// Force progress bar to 100% complete
	if pb.progressbar != nil && pb.progressbar.Current < pb.progressbar.Total {
		pb.progressbar.Current = pb.progressbar.Total
	}

	// Update title to show all workers active for visual consistency
	if pb.progressbar != nil {
		var titleBuf strings.Builder
		titleBuf.Grow(len(pb.bypassModule) + 100)
		titleBuf.WriteString(pterm.LightCyan(pb.bypassModule))
		titleBuf.WriteString(" | Workers [")
		titleBuf.WriteString(bytesutil.Itoa(pb.totalWorkers)) // Show full worker count
		titleBuf.WriteString("/")
		titleBuf.WriteString(bytesutil.Itoa(pb.totalWorkers))
		titleBuf.WriteString("] | Rate [")
		titleBuf.WriteString(bytesutil.Itoa(int(avgRate)))
		titleBuf.WriteString(" req/s] Peak [")
		titleBuf.WriteString(bytesutil.Itoa(int(peakRate)))
		titleBuf.WriteString(" req/s]")

		pb.progressbar.UpdateTitle(titleBuf.String())
	}

	// Force update to ensure display is correct
	if pb.progressbar != nil {
		pb.progressbar.UpdateTitle(pb.progressbar.Title)
	}
}
