package scanner

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

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

	scanningText := " | Scanning "
	offset := len(bypassModule) + len(scanningText)
	truncatedURL := truncateURL(targetURL, termWidth, offset)

	// Second use: calculate progress bar width based on truncated URL
	desiredWidth := len(truncatedURL) + len("Complete: ") + 10
	maxWidth := min(desiredWidth, termWidth)
	if maxWidth < 80 {
		maxWidth = min(80, termWidth)
	}

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
		MaxWidth:                  maxWidth,
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

func truncateURL(url string, termWidth int, offset int) string {
	maxURLWidth := termWidth - offset - 10 // Add extra padding for safety

	if len(url) <= maxURLWidth {
		return url
	}

	prefix := ""
	if strings.HasPrefix(url, "http://") {
		prefix = "http://"
	} else if strings.HasPrefix(url, "https://") {
		prefix = "https://"
	}

	remainingWidth := maxURLWidth - len(prefix)
	if remainingWidth < 20 { // Minimum reasonable width
		remainingWidth = 20
	}

	urlWithoutPrefix := strings.TrimPrefix(url, prefix)
	if len(urlWithoutPrefix) <= remainingWidth {
		return url
	}

	// Show domain part (up to first /) and end of path
	parts := strings.SplitN(urlWithoutPrefix, "/", 2)
	domain := parts[0]

	// Keep domain up to 30 chars max
	if len(domain) > 30 {
		domain = domain[:27] + "..."
	}

	if len(parts) < 2 {
		return prefix + domain
	}

	path := parts[1]

	// Calculate remaining space for the path
	pathSpace := remainingWidth - len(domain) - 4 // -4 for "/.."
	if pathSpace < 20 {
		// If very limited space, just show domain and indicate there's more
		return prefix + domain + "/..."
	}

	// Keep the last part of the path
	return prefix + domain + "/..." + path[len(path)-pathSpace:]
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
		titleBuf.WriteString(strconv.FormatInt(activeWorkers, 10))
		titleBuf.WriteString("/")
		titleBuf.WriteString(strconv.Itoa(pb.totalWorkers))
		titleBuf.WriteString("] | Rate [")
		titleBuf.WriteString(strconv.FormatUint(currentRate, 10))
		titleBuf.WriteString(" req/s] Avg [")
		titleBuf.WriteString(strconv.FormatUint(avgRate, 10))
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
		titleBuf.WriteString(strconv.Itoa(pb.totalWorkers)) // Show total workers instead of active
		titleBuf.WriteString("/")
		titleBuf.WriteString(strconv.Itoa(pb.totalWorkers))
		titleBuf.WriteString("] | Rate [")
		titleBuf.WriteString(strconv.FormatUint(avgRate, 10))
		titleBuf.WriteString(" req/s] Peak [") // Add peak rate
		titleBuf.WriteString(strconv.FormatUint(peakRate, 10))
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

	// Build initial spinner text
	spinnerBuf.Grow(len(pb.bypassModule) + len(pb.targetURL) + 20) // approximate size
	spinnerBuf.WriteString(pterm.LightCyan(pb.bypassModule))
	spinnerBuf.WriteString(" | Scanning ")
	spinnerBuf.WriteString(pterm.FgYellow.Sprint(pb.targetURL))
	initialSpinnerText := spinnerBuf.String()

	// Build initial progressbar title
	titleBuf.Grow(len(pb.bypassModule) + 50) // approximate size for stats
	titleBuf.WriteString(pterm.LightCyan(pb.bypassModule))
	titleBuf.WriteString(" | Workers [0/")
	titleBuf.WriteString(strconv.Itoa(pb.totalWorkers))
	titleBuf.WriteString("] | Rate [0 req/s] Avg [0 req/s]")
	progressTitle := titleBuf.String()

	if pb.multiprinter != nil {
		pb.multiprinter.Start()
	}

	if pb.spinner != nil {
		started, _ := pb.spinner.Start(initialSpinnerText)
		pb.spinner = started
	}

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

	if pb.progressbar != nil {
		// Ensure progress bar is at 100% before stopping
		if pb.progressbar.Current < pb.progressbar.Total {
			pb.progressbar.Current = pb.progressbar.Total
		}
		pb.progressbar.Stop()
	}

	if pb.spinner != nil {
		pb.spinner.Stop()
	}

	if pb.multiprinter != nil {
		pb.multiprinter.Stop()
	}

	// Print "a" newline to ensure proper spacing
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout)
}
