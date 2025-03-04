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

	// Fixed width progress bar that works well in most terminals
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

var stringBuilderPool = sync.Pool{
	New: func() any {
		return &strings.Builder{}
	},
}

func getStringBuilder() *strings.Builder {
	return stringBuilderPool.Get().(*strings.Builder)
}

func putStringBuilder(sb *strings.Builder) {
	sb.Reset()
	stringBuilderPool.Put(sb)
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

	spinnerBuf := getStringBuilder()
	defer putStringBuilder(spinnerBuf)

	titleBuf := getStringBuilder()
	defer putStringBuilder(titleBuf)

	// Spinner now shows statistics instead of URL
	spinnerBuf.WriteString(pb.coloredModule)
	spinnerBuf.WriteString(" | Workers [")
	spinnerBuf.WriteString(bytesutil.Itoa(int(activeWorkers)))
	spinnerBuf.WriteString("/")
	spinnerBuf.WriteString(bytesutil.Itoa(pb.totalWorkers))
	spinnerBuf.WriteString("] | Rate [")
	spinnerBuf.WriteString(bytesutil.Itoa(int(currentRate)))
	spinnerBuf.WriteString(" req/s] Avg [")
	spinnerBuf.WriteString(bytesutil.Itoa(int(avgRate)))
	spinnerBuf.WriteString(" req/s]")
	pb.spinner.UpdateText(spinnerBuf.String())

	// Progress bar title now shows module and URL
	if pb.progressbar != nil {
		titleBuf.WriteString(pb.coloredModule)
		titleBuf.WriteString(" | ")
		titleBuf.WriteString(pb.coloredURL)

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

	// First ensure progress bar is at 100% complete
	if pb.progressbar != nil && pb.progressbar.Current < pb.progressbar.Total {
		pb.progressbar.Current = pb.progressbar.Total
	}

	spinnerBuf := getStringBuilder()
	defer putStringBuilder(spinnerBuf)
	titleBuf := getStringBuilder()
	defer putStringBuilder(titleBuf)

	// Success spinner message shows module and stats
	spinnerBuf.WriteString(pb.coloredModule)
	spinnerBuf.WriteString(" | Workers [")
	spinnerBuf.WriteString(bytesutil.Itoa(pb.totalWorkers))
	spinnerBuf.WriteString("/")
	spinnerBuf.WriteString(bytesutil.Itoa(pb.totalWorkers))
	spinnerBuf.WriteString("] | Rate [")
	spinnerBuf.WriteString(bytesutil.Itoa(int(avgRate)))
	spinnerBuf.WriteString(" req/s] Peak [")
	spinnerBuf.WriteString(bytesutil.Itoa(int(peakRate)))
	spinnerBuf.WriteString(" req/s]")

	// Progress bar title remains with module and URL
	if pb.progressbar != nil {
		titleBuf.WriteString(pb.coloredModule)
		titleBuf.WriteString(" | ")
		titleBuf.WriteString(pb.coloredURL)
		pb.progressbar.UpdateTitle(titleBuf.String())
	}

	// Final progressbar update to ensure display is correct
	if pb.progressbar != nil {
		pb.progressbar.UpdateTitle(pb.progressbar.Title)
	}

	// Now show success message - this should be the last operation
	pb.spinner.Success(spinnerBuf.String())
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
	spinnerBuf := getStringBuilder()
	defer putStringBuilder(spinnerBuf)

	titleBuf := getStringBuilder()
	defer putStringBuilder(titleBuf)

	// Build initial spinner text - now shows module and initial stats
	spinnerBuf.WriteString(pb.coloredModule)
	spinnerBuf.WriteString(" | Workers [0/")
	spinnerBuf.WriteString(bytesutil.Itoa(pb.totalWorkers))
	spinnerBuf.WriteString("] | Rate [0 req/s] Avg [0 req/s]")
	initialSpinnerText := spinnerBuf.String()

	// Build initial progressbar title - now shows module and URL
	titleBuf.WriteString(pb.coloredModule)
	titleBuf.WriteString(" | ")
	titleBuf.WriteString(pb.coloredURL)
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
		//time.Sleep(50 * time.Millisecond)
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
