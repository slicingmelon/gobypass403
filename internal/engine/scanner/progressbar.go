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
	totalJobs    int
	totalWorkers int
}

// NewProgressBar creates a new progress display for a bypass module
func NewProgressBar(bypassModule string, totalJobs int, totalWorkers int) *ProgressBar {
	//multi := pterm.DefaultMultiPrinter

	multi := &pterm.MultiPrinter{
		Writer:      os.Stdout,
		UpdateDelay: time.Millisecond * 200,
		// buffers and area will be initialized by pterm internally
	}

	// initialText := bypassModule +
	// 	" - Total Workers: " + strconv.Itoa(totalWorkers) +
	// 	" - Active Workers: 0" +
	// 	" - Requests: 0/" + strconv.Itoa(totalJobs) +
	// 	" - Rate: 0 req/s"

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

	//spinner, _ := spinnerPrinter.Start(initialText)
	//progressbar, _ := progressPrinter.Start(bypassModule)

	return &ProgressBar{
		multiprinter: multi,
		spinner:      spinnerPrinter,
		progressbar:  progressPrinter,
		mu:           sync.RWMutex{},
		bypassModule: bypassModule,
		totalJobs:    totalJobs,
		totalWorkers: totalWorkers,
	}

}

// Increment advances the progress bar by one step
func (pb *ProgressBar) Increment() {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	if pb.progressbar != nil {
		pb.progressbar.Add(1)

		// Ensure we don't exceed 100%
		if pb.progressbar.Current > pb.progressbar.Total {
			pb.progressbar.Current = pb.progressbar.Total
		}
	}
}

// UpdateSpinnerText updates the spinner text
func (pb *ProgressBar) UpdateSpinnerText(
	bypassModule string,
	totalWorkers int,
	activeWorkers int64, // from GetReqWPActiveWorkers(),
	completedTasks uint64, // from GetReqWPCompletedTasks()
	submittedTasks uint64, // from GetReqWPSubmittedTasks()
	currentRate uint64, // from GetRequestRate()
	avgRate uint64, // from GetAverageRequestRate()
) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	text := bypassModule +
		" - Workers: " + strconv.Itoa(totalWorkers) +
		" (" + strconv.FormatInt(activeWorkers, 10) + " active)" +
		" - Requests: " + strconv.FormatUint(completedTasks, 10) +
		"/" + strconv.FormatUint(submittedTasks, 10) +
		" - Rate: " + strconv.FormatUint(currentRate, 10) + " req/s" +
		" - Completed Rate: " + strconv.FormatUint(avgRate, 10) + " req/s"
	pb.spinner.UpdateText(text)
}

// SpinnerSuccess marks the spinner as complete with success message
func (pb *ProgressBar) SpinnerSuccess(
	bypassModule string,
	totalWorkers int,
	activeWorkers int64,
	completedTasks uint64,
	submittedTasks uint64,
	currentRate uint64,
	avgRate uint64,
	peakRate uint64,
) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	// First ensure progress bar is at 100%
	if pb.progressbar != nil && pb.progressbar.Current < pb.progressbar.Total {
		pb.progressbar.Current = pb.progressbar.Total
	}

	text := bypassModule +
		" - Workers: " + strconv.Itoa(totalWorkers) +
		" - Completed: " + strconv.FormatUint(completedTasks, 10) +
		"/" + strconv.FormatUint(submittedTasks, 10) +
		" - Avg Rate: " + strconv.FormatUint(avgRate, 10) + " req/s" +
		" - Peak Rate: " + strconv.FormatUint(peakRate, 10) + " req/s"

	// Print a newline before success message
	//fmt.Fprintln(os.Stdout)
	pb.spinner.Success(text)
	// Print another newline after success message
	//fmt.Fprintln(os.Stdout)
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

	initialSpinnerText := pb.bypassModule +
		" - Workers: " + strconv.Itoa(pb.totalWorkers) +
		" (0 active)" +
		" - Requests: 0/" + strconv.Itoa(pb.totalJobs) +
		" - Rate: 0 req/s" +
		" - Completed Rate: 0 req/s"

	if pb.multiprinter != nil {
		pb.multiprinter.Start()
	}

	if pb.spinner != nil {
		started, _ := pb.spinner.Start(initialSpinnerText)
		pb.spinner = started
	}

	if pb.progressbar != nil {
		started, _ := pb.progressbar.Start(pb.bypassModule)
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
}
