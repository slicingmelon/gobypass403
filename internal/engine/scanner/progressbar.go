package scanner

import (
	"strconv"

	"github.com/pterm/pterm"
)

// ProgressBar manages a combined spinner and progress bar display
type ProgressBar struct {
	multiprinter *pterm.MultiPrinter
	spinner      *pterm.SpinnerPrinter
	progressbar  *pterm.ProgressbarPrinter
}

// NewProgressBar creates a new progress display for a bypass module
func NewProgressBar(bypassModule string, totalJobs int, totalWorkers int) *ProgressBar {
	multi := pterm.DefaultMultiPrinter

	initialText := bypassModule +
		" - Total Workers: " + strconv.Itoa(totalWorkers) +
		" - Active Workers: 0" +
		" - Requests: 0/" + strconv.Itoa(totalJobs) +
		" - Request Rate: 0req/s"

	spinner, _ := pterm.DefaultSpinner.WithWriter(multi.NewWriter()).Start(initialText)
	progressbar, _ := pterm.DefaultProgressbar.
		WithTotal(totalJobs).
		WithWriter(multi.NewWriter()).
		Start(bypassModule)

	multi.Start()

	return &ProgressBar{
		multiprinter: &multi,
		spinner:      spinner,
		progressbar:  progressbar,
	}
}

// Increment advances the progress bar by one step
func (pb *ProgressBar) Increment() {
	pb.progressbar.Increment()
}

// UpdateSpinnerText updates the spinner text
func (pb *ProgressBar) UpdateSpinnerText(bypassModule string, totalWorkers int, activeWorkers int, completedTasks int, submittedTasks int, reqRate uint64) {
	text := bypassModule +
		" - Total Workers: " + strconv.Itoa(totalWorkers) +
		" - Active Workers: " + strconv.Itoa(activeWorkers) +
		" - Requests: " + strconv.Itoa(completedTasks) +
		"/" + strconv.Itoa(submittedTasks) +
		" - Request Rate: " + strconv.FormatUint(reqRate, 10) + "req/s"

	pb.spinner.UpdateText(text)
}

// SpinnerSuccess marks the spinner as complete with success message
func (pb *ProgressBar) SpinnerSuccess(bypassModule string, totalWorkers int, activeWorkers int, completedTasks int, submittedTasks int, avgReqRate uint64, peakReqRate uint64) {
	text := bypassModule +
		" - Total Workers: " + strconv.Itoa(totalWorkers) +
		" - Active Workers: " + strconv.Itoa(activeWorkers) +
		" - Requests: " + strconv.Itoa(completedTasks) +
		"/" + strconv.Itoa(submittedTasks) +
		" - Average Request Rate: " + strconv.FormatUint(avgReqRate, 10) + "req/s" +
		" - Peak Request Rate: " + strconv.FormatUint(peakReqRate, 10) + "req/s"

	pb.spinner.Success(text)
}

// Stop terminates the progress display
func (pb *ProgressBar) Stop() {
	pb.multiprinter.Stop()
}

// UpdateProgressbarTitle updates the progress bar title
func (pb *ProgressBar) UpdateProgressbarTitle(title string) {
	pb.progressbar.UpdateTitle(title)
}
