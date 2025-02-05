package scanner

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pterm/pterm"
)

// ModuleStats tracks statistics for each bypass module
type ModuleStats struct {
	TotalJobs     int64
	CompletedJobs atomic.Int64
	ActiveWorkers atomic.Int64
	StartTime     time.Time
	ReqPerSec     float64
}

// ProgressCounter manages progress bars and stats for bypass modules
type ProgressCounter struct {
	multi         pterm.MultiPrinter // Correct type without pointer
	moduleStats   map[string]*ModuleStats
	progressBars  map[string]*pterm.ProgressbarPrinter
	mu            sync.RWMutex
	activeModules atomic.Int32
}

func NewProgressCounter() *ProgressCounter {
	return &ProgressCounter{
		multi:        pterm.DefaultMultiPrinter, // Use directly, no dereferencing
		moduleStats:  make(map[string]*ModuleStats),
		progressBars: make(map[string]*pterm.ProgressbarPrinter),
	}
}

// StartModule initializes tracking for a new bypass module
func (pc *ProgressCounter) StartModule(moduleName string, totalJobs int, targetURL string) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	// Initialize module stats
	pc.moduleStats[moduleName] = &ModuleStats{
		TotalJobs: int64(totalJobs),
		StartTime: time.Now(),
	}

	// Create progress bar
	pb, _ := pterm.DefaultProgressbar.
		WithTotal(totalJobs).
		WithTitle(pterm.FgCyan.Sprintf("[%s]", moduleName)).
		WithWriter(pc.multi.NewWriter()).
		WithShowCount(true).
		WithShowPercentage(true).
		Start()

	pc.progressBars[moduleName] = pb
	pc.activeModules.Add(1)

	// Start multi printer for first module
	if pc.activeModules.Load() == 1 {
		pc.multi.Start()
	}

	// Print initial module info
	pterm.Info.Printf("[%s] Generated %d payloads for %s", moduleName, totalJobs, targetURL)
}

// UpdateWorkerStats updates the active worker count for a module
func (pc *ProgressCounter) UpdateWorkerStats(moduleName string, activeWorkers int64) {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	if stats := pc.moduleStats[moduleName]; stats != nil {
		oldWorkers := stats.ActiveWorkers.Load()
		if activeWorkers == 0 || oldWorkers == 0 ||
			math.Abs(float64(activeWorkers-oldWorkers))/float64(oldWorkers) > 0.1 {
			stats.ActiveWorkers.Store(activeWorkers)
			if pb := pc.progressBars[moduleName]; pb != nil {
				title := pterm.FgCyan.Sprintf("[%s] (%d workers)", moduleName, activeWorkers)
				pb.UpdateTitle(title)
			}
		}
	}
}

// IncrementProgress updates progress for a module
func (pc *ProgressCounter) IncrementProgress(moduleName string) {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	if stats := pc.moduleStats[moduleName]; stats != nil {
		stats.CompletedJobs.Add(1)
		if pb := pc.progressBars[moduleName]; pb != nil {
			pb.Increment()
		}
	}
}

// MarkModuleAsDone finalizes a module and prints completion stats
func (pc *ProgressCounter) MarkModuleAsDone(moduleName string) {
	pc.mu.RLock()
	stats := pc.moduleStats[moduleName]
	pb := pc.progressBars[moduleName]
	pc.mu.RUnlock()

	if stats != nil && pb != nil {
		// Calculate final stats
		duration := time.Since(stats.StartTime)
		reqPerSec := float64(stats.CompletedJobs.Load()) / duration.Seconds()
		stats.ReqPerSec = reqPerSec

		// Print completion message
		pterm.Success.Printf("[%s] Completed %d requests in %s (%.2f req/s)",
			moduleName,
			stats.CompletedJobs.Load(),
			duration.Round(time.Millisecond),
			reqPerSec)

		pc.activeModules.Add(-1)

		// Stop multi printer if all modules complete
		if pc.activeModules.Load() == 0 {
			pc.multi.Stop()
		}
	}
}

// Stop stops all progress tracking
func (pc *ProgressCounter) Stop() {
	pc.multi.Stop()
}
