package scanner

import (
	"fmt"
	"os"
	"strconv"
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
	multi := &pterm.MultiPrinter{
		Writer:      os.Stdout,
		UpdateDelay: time.Millisecond * 200,
	}

	spinnerPrinter := &pterm.SpinnerPrinter{
		Sequence:            []string{"▀ ", " ▀", " ▄", "▄ "},
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
		MaxWidth:                  80,
		Writer:                    multi.NewWriter(),
	}

	return &ProgressBar{
		multiprinter: multi,
		spinner:      spinnerPrinter,
		progressbar:  progressPrinter,
		mu:           sync.RWMutex{},
		bypassModule: bypassModule,
		targetURL:    targetURL,
		totalJobs:    totalJobs,
		totalWorkers: totalWorkers,
	}

}

func padNumber(num, length int) string {
	s := strconv.Itoa(num)
	for len(s) < length {
		s = "0" + s
	}
	return s
}

// Increment advances the progress bar by one step
func (pb *ProgressBar) Increment() {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	if pb.progressbar != nil {
		pb.progressbar.Add(1)

		// Update title with current progress
		current := pb.progressbar.Current
		total := pb.progressbar.Total
		currentPad := padNumber(current, 4)
		totalPad := padNumber(total, 4)

		// Create new progressbar instance with updated title
		updatedBar := *pb.progressbar
		updatedBar.Title = pb.bypassModule + " [" + currentPad + "/" + totalPad + "]"
		*pb.progressbar = updatedBar

		// Ensure we don't exceed 100%
		if current > total {
			pb.progressbar.Current = total
		}
	}
}

// UpdateSpinnerText updates the spinner text
func (pb *ProgressBar) UpdateSpinnerText(
	activeWorkers int64,
	completedTasks uint64,
	submittedTasks uint64,
	currentRate uint64,
	avgRate uint64,
) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	text := pb.bypassModule + " - Scanning " + pb.targetURL + ".. | " +
		"Workers: " + strconv.Itoa(pb.totalWorkers) +
		" (" + strconv.FormatInt(activeWorkers, 10) + " active)" +
		" - Requests: " + strconv.FormatUint(completedTasks, 10) +
		"/" + strconv.FormatUint(submittedTasks, 10) +
		" - Rate: " + strconv.FormatUint(currentRate, 10) + " req/s" +
		" - Completed Rate: " + strconv.FormatUint(avgRate, 10) + " req/s"

	pb.spinner.UpdateText(text)
}

// SpinnerSuccess marks the spinner as complete with success message
func (pb *ProgressBar) SpinnerSuccess(
	completedTasks uint64,
	submittedTasks uint64,
	avgRate uint64,
	peakRate uint64,
) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	text := pb.bypassModule + " - Scan complete for " + pb.targetURL +
		" - Workers: " + strconv.Itoa(pb.totalWorkers) +
		" - Completed: " + strconv.FormatUint(completedTasks, 10) +
		"/" + strconv.FormatUint(submittedTasks, 10) +
		" - Avg Rate: " + strconv.FormatUint(avgRate, 10) + " req/s" +
		" - Peak Rate: " + strconv.FormatUint(peakRate, 10) + " req/s"

	pb.spinner.Success(text)
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

	// Build spinner text with target URL
	initialSpinnerText := pb.bypassModule + " - Scanning " + pb.targetURL + ".. | " +
		"Workers: " + strconv.Itoa(pb.totalWorkers) +
		" (0 active) - Requests: 0/" + strconv.Itoa(pb.totalJobs) +
		" - Rate: 0 req/s - Completed Rate: 0 req/s"

	// Build progress title with padded numbers
	currentPad := padNumber(0, 4)
	totalPad := padNumber(pb.totalJobs, 4)
	progressTitle := pb.bypassModule + " [" + currentPad + "/" + totalPad + "]"

	if pb.multiprinter != nil {
		pb.multiprinter.Start()
	}

	if pb.spinner != nil {
		started, _ := pb.spinner.Start(initialSpinnerText)
		pb.spinner = started
	}

	if pb.progressbar != nil {
		// Clone existing progressbar config with new title
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

	// Print a newline to ensure proper spacing
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout)
}
