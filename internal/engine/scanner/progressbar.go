package scanner

import (
	"strconv"
	"sync"

	"github.com/pterm/pterm"
)

// ProgressBar manages a combined spinner and progress bar display
type ProgressBar struct {
	multiprinter *pterm.MultiPrinter
	spinner      *pterm.SpinnerPrinter
	progressbar  *pterm.ProgressbarPrinter
	mu           sync.Mutex
}

// NewProgressBar creates a new progress display for a bypass module
func NewProgressBar(bypassModule string, totalJobs int, totalWorkers int) *ProgressBar {
	multi := pterm.DefaultMultiPrinter

	initialText := bypassModule +
		" - Total Workers: " + strconv.Itoa(totalWorkers) +
		" - Active Workers: 0" +
		" - Requests: 0/" + strconv.Itoa(totalJobs) +
		" - Rate: 0 req/s"

	spinner, _ := pterm.DefaultSpinner.WithWriter(multi.NewWriter()).Start(initialText)
	progressbar, _ := pterm.DefaultProgressbar.
		WithTotal(totalJobs).
		WithWriter(multi.NewWriter()).
		Start(bypassModule)

	//multi.Start()

	return &ProgressBar{
		multiprinter: &multi,
		spinner:      spinner,
		progressbar:  progressbar,
		mu:           sync.Mutex{},
	}

}

// Increment advances the progress bar by one step
func (pb *ProgressBar) Increment() {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	pb.progressbar.Increment()
}

// UpdateSpinnerText updates the spinner text
func (pb *ProgressBar) UpdateSpinnerText(
	bypassModule string,
	totalWorkers int,
	activeWorkers int,
	completedTasks int,
	submittedTasks int,
	currentRate uint64,
	avgRate uint64,
) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	text := bypassModule +
		" - Workers: " + strconv.Itoa(totalWorkers) +
		" (" + strconv.Itoa(activeWorkers) + " active)" +
		" - Requests: " + strconv.Itoa(completedTasks) +
		"/" + strconv.Itoa(submittedTasks) +
		" - Rate: " + strconv.FormatUint(currentRate, 10) + " req/s" +
		" - Completed Rate: " + strconv.FormatUint(avgRate, 10) + " req/s"

	pb.spinner.UpdateText(text)
}

// SpinnerSuccess marks the spinner as complete with success message
func (pb *ProgressBar) SpinnerSuccess(
	bypassModule string,
	totalWorkers int,
	activeWorkers int,
	completedTasks int,
	submittedTasks int,
	currentRate uint64,
	avgRate uint64,
	peakRate uint64,
) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	text := bypassModule +
		" - Workers: " + strconv.Itoa(totalWorkers) +
		" - Completed: " + strconv.Itoa(completedTasks) +
		"/" + strconv.Itoa(submittedTasks) +
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

	if pb.multiprinter != nil {
		pb.multiprinter.Start()
	}
}

// Stop terminates the progress display
func (pb *ProgressBar) Stop() {
	pb.mu.Lock()

	defer pb.mu.Unlock()

	if pb.multiprinter != nil {
		pb.multiprinter.Stop()
	}
	if pb.spinner != nil {
		pb.spinner.Stop()
	}
	if pb.progressbar != nil {
		pb.progressbar.Stop()
	}
}
