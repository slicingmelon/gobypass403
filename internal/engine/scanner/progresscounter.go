package scanner

import (
	"fmt"
	"sync"
)

const (
	colorCyan   = "\033[36m"
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorOrange = "\033[33m"
	colorTeal   = "\033[36m"
)

// ----------------------------------------------------------------//
// ProgressCounter //
// Custom code to show progress on the current bypass mode
type ProgressCounter struct {
	Total     int
	Current   int
	Mode      string
	URL       string // Add URL field
	Mu        sync.Mutex
	Cancelled bool
}

func (pc *ProgressCounter) summarizeProgress() {
	pc.Mu.Lock()
	defer pc.Mu.Unlock()

	fmt.Printf("\r%s[%s]%s %sCompleted:%s %s%d%s/%s%d%s (%s%.1f%%%s) requests\n",
		colorCyan, pc.Mode, colorReset,
		colorTeal, colorReset,
		colorYellow, pc.Current, colorReset,
		colorGreen, pc.Total, colorReset,
		colorYellow, float64(pc.Current)/float64(pc.Total)*100, colorReset,
	)
}

func (pc *ProgressCounter) markAsCancelled() {
	pc.Mu.Lock()
	if !pc.Cancelled {
		pc.Cancelled = true
		fmt.Printf("\r%s[%s]%s %sCancelled at:%s %s%d%s/%s%d%s (%s%.1f%%%s) - %s%s%s\n",
			colorCyan, pc.Mode, colorReset,
			colorRed, colorReset,
			colorRed, pc.Current, colorReset,
			colorGreen, pc.Total, colorReset,
			colorRed, float64(pc.Current)/float64(pc.Total)*100, colorReset,
			colorYellow, "Permanent error detected - Skipping current job", colorReset,
		)
	}
	pc.Mu.Unlock()
}

func (pc *ProgressCounter) increment() {
	pc.Mu.Lock()
	defer pc.Mu.Unlock()

	if pc.Cancelled {
		return
	}

	pc.Current++

	// Calculate percentage
	percentage := float64(pc.Current) / float64(pc.Total) * 100

	// Color for current count based on progress
	var currentColor string
	switch {
	case percentage <= 25:
		currentColor = colorRed
	case percentage <= 50:
		currentColor = colorOrange
	case percentage <= 75:
		currentColor = colorYellow
	default:
		currentColor = colorGreen
	}

	// Print URL only once at the start
	if pc.Current == 1 {
		fmt.Printf("%s[+] Scanning %s ...%s\n", colorCyan, pc.URL, colorReset)
	}

	// Print progress on same line
	fmt.Printf("\r%s[%s]%s %sProgress:%s %s%d%s/%s%d%s (%s%.1f%%%s)",
		colorCyan, pc.Mode, colorReset,
		colorTeal, colorReset,
		currentColor, pc.Current, colorReset,
		colorGreen, pc.Total, colorReset,
		currentColor, percentage, colorReset,
	)

	if pc.Current == pc.Total {
		fmt.Printf("\n")
	}
}

func (pc *ProgressCounter) isCancelled() bool {
	pc.Mu.Lock()
	defer pc.Mu.Unlock()
	return pc.Cancelled
}
