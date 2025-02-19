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
	urlSpinner   *pterm.SpinnerPrinter // New spinner for URL
	statsSpinner *pterm.SpinnerPrinter // Renamed from spinner
	progressbar  *pterm.ProgressbarPrinter
	currentURL   string
	mu           sync.RWMutex
	bypassModule string
	totalJobs    int
	totalWorkers int
}

// NewProgressBar creates a new progress display for a bypass module
func NewProgressBar(bypassModule string, totalJobs int, totalWorkers int) *ProgressBar {
	multi := &pterm.MultiPrinter{
		Writer:      os.Stdout,
		UpdateDelay: time.Millisecond * 200,
	}

	// URL Spinner - Cyan theme
	urlSpinner := &pterm.SpinnerPrinter{
		Sequence:     []string{"▀ ", " ▀", " ▄", "▄ "},
		Style:        &pterm.Style{pterm.FgCyan},
		Delay:        time.Millisecond * 200,
		MessageStyle: &pterm.Style{pterm.FgCyan},
		ShowTimer:    false,
		Writer:       multi.NewWriter(),
	}

	// Stats Spinner - Blue theme
	statsSpinner := &pterm.SpinnerPrinter{
		Sequence:     []string{"▀ ", " ▀", " ▄", "▄ "},
		Style:        &pterm.Style{pterm.FgBlue},
		Delay:        time.Millisecond * 200,
		MessageStyle: &pterm.Style{pterm.FgBlue},
		SuccessPrinter: &pterm.PrefixPrinter{
			MessageStyle: &pterm.Style{pterm.FgGreen},
			Prefix: pterm.Prefix{
				Text:  " SUCCESS ",
				Style: &pterm.Style{pterm.BgGreen, pterm.FgBlack},
			},
		},
		ShowTimer:           true,
		TimerRoundingFactor: time.Second,
		TimerStyle:          &pterm.Style{pterm.FgGray},
		Writer:              multi.NewWriter(),
	}

	// Progress bar - Cyan/Blue gradient
	progressPrinter := &pterm.ProgressbarPrinter{
		Total:                     totalJobs,
		BarCharacter:              "█",
		LastCharacter:             "█",
		ElapsedTimeRoundingFactor: time.Second,
		BarStyle:                  &pterm.Style{pterm.FgCyan},
		TitleStyle:                &pterm.Style{pterm.FgBlue},
		ShowTitle:                 true,
		ShowCount:                 true,
		ShowPercentage:            true,
		ShowElapsedTime:           true,
		BarFiller:                 pterm.Gray("░"),
		MaxWidth:                  80,
		Writer:                    multi.NewWriter(),
	}

	return &ProgressBar{
		multiprinter: multi,
		urlSpinner:   urlSpinner,
		statsSpinner: statsSpinner,
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
	activeWorkers int64,
	completedTasks uint64,
	submittedTasks uint64,
	currentRate uint64,
	avgRate uint64,
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
	pb.statsSpinner.UpdateText(text)
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

	// Ensure progress bar is at 100%
	if pb.progressbar != nil && pb.progressbar.Current < pb.progressbar.Total {
		pb.progressbar.Current = pb.progressbar.Total
	}

	// Stats text
	statsText := bypassModule +
		" - Workers: " + strconv.Itoa(totalWorkers) +
		" - Completed: " + strconv.FormatUint(completedTasks, 10) +
		"/" + strconv.FormatUint(submittedTasks, 10) +
		" - Avg Rate: " + strconv.FormatUint(avgRate, 10) + " req/s" +
		" - Peak Rate: " + strconv.FormatUint(peakRate, 10) + " req/s"

	if pb.urlSpinner != nil {
		pb.urlSpinner.Success(bypassModule + " Scan completed for " + pb.currentURL)
	}

	// Then show stats success
	if pb.statsSpinner != nil {
		pb.statsSpinner.Success(statsText)
	}
}

// UpdateProgressbarTitle updates the progress bar title
func (pb *ProgressBar) UpdateProgressbarTitle(title string) {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	pb.progressbar.UpdateTitle(title)
}

func (pb *ProgressBar) UpdateCurrentURL(url string) {
	pb.mu.Lock()
	pb.currentURL = url
	text := pb.bypassModule + " Scanning " + url
	pb.urlSpinner.UpdateText(text)
	pb.mu.Unlock()
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

	if pb.statsSpinner != nil { // Changed from spinner to statsSpinner
		started, _ := pb.statsSpinner.Start(initialSpinnerText)
		pb.statsSpinner = started
	}

	if pb.progressbar != nil {
		started, _ := pb.progressbar.Start(pb.bypassModule)
		pb.progressbar = started
	}
	if pb.urlSpinner != nil {
		pb.urlSpinner.Success(pb.bypassModule + " Scan completed")
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

	if pb.urlSpinner != nil {
		pb.urlSpinner.Stop()
	}

	if pb.statsSpinner != nil {
		pb.statsSpinner.Stop()
	}

	if pb.multiprinter != nil {
		pb.multiprinter.Stop()
	}

	// Print a newline to ensure proper spacing
	fmt.Fprintln(os.Stdout)
}
