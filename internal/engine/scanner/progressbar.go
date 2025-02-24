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
	totalJobs    int
	totalWorkers int
}

// NewProgressBar creates a new progress display for a bypass module
func NewProgressBar(bypassModule string, targetURL string, totalJobs int, totalWorkers int) *ProgressBar {
	termWidth := pterm.GetTerminalWidth()

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
		MaxWidth:                  termWidth,
		Writer:                    multi.NewWriter(),
	}

	return &ProgressBar{
		multiprinter: multi,
		spinner:      spinnerPrinter,
		progressbar:  progressPrinter,
		mu:           sync.RWMutex{},
		bypassModule: bypassModule,
		targetURL:    truncateURL(targetURL, termWidth),
		totalJobs:    totalJobs,
		totalWorkers: totalWorkers,
	}
}

func truncateURL(url string, termWidth int) string {
	// Reserve space for module name, status text, and some padding
	// Example: "module_name | Scanning " = ~20 chars
	reservedSpace := 20
	maxURLWidth := termWidth - reservedSpace

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
	if remainingWidth < 10 {
		remainingWidth = 10
	}

	// Split remaining width between start and end of URL
	startLen := remainingWidth / 2
	endLen := remainingWidth - startLen - 3 // -3 for "..."

	urlWithoutPrefix := strings.TrimPrefix(url, prefix)
	if len(urlWithoutPrefix) <= remainingWidth {
		return url
	}

	return prefix + urlWithoutPrefix[:startLen] + "..." + urlWithoutPrefix[len(urlWithoutPrefix)-endLen:]
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
	spinnerBuf.Grow(len(pb.bypassModule) + len(pb.targetURL) + 20)
	spinnerBuf.WriteString(pterm.LightCyan(pb.bypassModule))
	spinnerBuf.WriteString(" | Scanning ")
	spinnerBuf.WriteString(pterm.FgYellow.Sprint(pb.targetURL))
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

	// Spinner completion message
	var spinnerBuf strings.Builder
	spinnerBuf.Grow(len(pb.targetURL) + 20)
	spinnerBuf.WriteString(pterm.White("Complete"))
	spinnerBuf.WriteString(": ")
	spinnerBuf.WriteString(pterm.FgYellow.Sprint(pb.targetURL))
	pb.spinner.Success(spinnerBuf.String())

	// Update final progressbar title
	if pb.progressbar != nil {
		var titleBuf strings.Builder
		titleBuf.Grow(len(pb.bypassModule) + 100)
		titleBuf.WriteString(pterm.LightCyan(pb.bypassModule))
		titleBuf.WriteString(" | Requests: ")
		titleBuf.WriteString(strconv.FormatUint(completedTasks, 10))
		titleBuf.WriteString("/")
		titleBuf.WriteString(strconv.FormatUint(submittedTasks, 10))
		titleBuf.WriteString(" | Avg: [")
		titleBuf.WriteString(strconv.FormatUint(avgRate, 10))
		titleBuf.WriteString(" req/s] | Peak: [")
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
