package scanner

import (
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
}

// NewProgressBar creates a new progress display for a bypass module
func NewProgressBar(bypassModule string, totalJobs int, totalWorkers int) *ProgressBar {
	//multi := pterm.DefaultMultiPrinter

	multi := &pterm.MultiPrinter{
		Writer:      os.Stdout,
		UpdateDelay: time.Millisecond * 200,
		// buffers and area will be initialized by pterm internally
	}

	initialText := bypassModule +
		" - Total Workers: " + strconv.Itoa(totalWorkers) +
		" - Active Workers: 0" +
		" - Requests: 0/" + strconv.Itoa(totalJobs) +
		" - Rate: 0 req/s"

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

	spinner, _ := spinnerPrinter.Start(initialText)
	progressbar, _ := progressPrinter.Start(bypassModule)

	return &ProgressBar{
		multiprinter: multi,
		spinner:      spinner,
		progressbar:  progressbar,
		mu:           sync.RWMutex{},
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
