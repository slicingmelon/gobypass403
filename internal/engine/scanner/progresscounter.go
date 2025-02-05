package scanner

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jedib0t/go-pretty/v6/progress"
	"github.com/jedib0t/go-pretty/v6/text"
)

type ModuleStats struct {
	TotalJobs      atomic.Int64
	CompletedJobs  atomic.Int64
	SuccessfulJobs atomic.Int64
	FailedJobs     atomic.Int64
	ActiveWorkers  atomic.Int64
	StartTime      time.Time
}

type ProgressCounter struct {
	ProgressWriter progress.Writer
	Trackers       map[string]*progress.Tracker
	ModuleStats    map[string]*ModuleStats
	mu             sync.RWMutex
	ActiveModules  atomic.Int32
	Stopped        atomic.Bool
}

func NewProgressCounter() *ProgressCounter {
	pw := progress.NewWriter()
	pw.SetUpdateFrequency(100 * time.Millisecond)
	pw.SetTrackerLength(45)
	pw.SetMessageLength(45)
	pw.SetAutoStop(false)
	pw.SetSortBy(progress.SortByPercentDsc)
	style := progress.StyleBlocks
	style.Colors = progress.StyleColors{
		Message: text.Colors{text.FgCyan},
		Error:   text.Colors{text.FgRed},
		Stats:   text.Colors{text.FgHiBlack},
		Time:    text.Colors{text.FgGreen},
		Value:   text.Colors{text.FgYellow},
		Speed:   text.Colors{text.FgMagenta},
		Percent: text.Colors{text.FgHiCyan},

		Pinned: text.Colors{text.BgHiBlack, text.FgWhite, text.Bold},
	}
	// Enhanced options
	style.Options = progress.StyleOptions{
		DoneString:    "✅",
		ErrorString:   "❌",
		Separator:     " │ ",
		PercentFormat: "%4.1f%%",
		SpeedPosition: progress.PositionRight,
		SpeedSuffix:   " req/s",

		SnipIndicator: "~",
	}
	// Enhanced visibility settings
	style.Visibility = progress.StyleVisibility{
		ETA:            false,
		ETAOverall:     true,
		Percentage:     true,
		Speed:          true,
		Time:           true,
		Tracker:        true,
		TrackerOverall: true,
		Value:          true,
		Pinned:         true,
	}
	pw.SetStyle(style)
	pw.SetTrackerPosition(progress.PositionRight)
	return &ProgressCounter{
		ProgressWriter: pw,
		Trackers:       make(map[string]*progress.Tracker),
		ModuleStats:    make(map[string]*ModuleStats),
	}

}

func (pc *ProgressCounter) StartModule(moduleName string, totalJobs int, targetURL string) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.ActiveModules.Add(1)
	pc.ModuleStats[moduleName] = &ModuleStats{
		TotalJobs: atomic.Int64{},
		StartTime: time.Now(),
	}

	pc.ModuleStats[moduleName].TotalJobs.Store(int64(totalJobs))

	tracker := &progress.Tracker{
		Message: fmt.Sprintf("[%s] (0 active workers)", moduleName),
		Total:   int64(totalJobs),
		Units:   progress.UnitsDefault,
	}
	pc.Trackers[moduleName+"_progress"] = tracker
	pc.ProgressWriter.AppendTracker(tracker)

	pc.ProgressWriter.Log("")
	pc.ProgressWriter.Log(text.FgCyan.Sprintf("Target URL: %s", targetURL))
	pc.ProgressWriter.Log(text.FgYellow.Sprintf("Active Module: %s", moduleName))
	pc.ProgressWriter.Log(text.FgGreen.Sprintf("Started: %s", time.Now().Format("15:04:05")))

	pc.ProgressWriter.Log(text.FgHiBlack.Sprintf("Total Jobs: %d", totalJobs))
	pc.ProgressWriter.Log("")

	go pc.ProgressWriter.Render()
}

func (pc *ProgressCounter) addTracker(id, message string, total int64) {

	tracker := &progress.Tracker{
		Message: message,
		Total:   total,
		Units:   progress.UnitsDefault,
	}
	pc.Trackers[id] = tracker
	pc.ProgressWriter.AppendTracker(tracker)
}

func (pc *ProgressCounter) UpdateWorkerStats(moduleName string, totalWorkers int64) {
	pc.mu.RLock()
	stats, exists := pc.ModuleStats[moduleName]

	tracker := pc.Trackers[moduleName+"_progress"]
	pc.mu.RUnlock()

	if exists {
		stats.ActiveWorkers.Store(totalWorkers)

		if tracker != nil {
			newMessage := fmt.Sprintf("[%s] (%d active workers)", moduleName, totalWorkers)
			tracker.UpdateMessage(newMessage)
		}
	}
}

func (pc *ProgressCounter) IncrementProgress(moduleName string, success bool) {
	pc.mu.RLock()
	stats, exists := pc.ModuleStats[moduleName]
	tracker := pc.Trackers[moduleName+"_progress"]
	pc.mu.RUnlock()

	if exists && tracker != nil {
		stats.CompletedJobs.Add(1)
		if success {
			stats.SuccessfulJobs.Add(1)
		} else {
			stats.FailedJobs.Add(1)
		}
		tracker.Increment(1)
	}
}

func (pc *ProgressCounter) MarkModuleAsDone(moduleName string) {
	pc.mu.RLock()
	tracker := pc.Trackers[moduleName+"_progress"]
	stats := pc.ModuleStats[moduleName]
	pc.mu.RUnlock()

	if tracker != nil && stats != nil {
		completedJobs := stats.CompletedJobs.Load()
		//successfulJobs := stats.SuccessfulJobs.Load()
		//failedJobs := stats.FailedJobs.Load()
		duration := time.Since(stats.StartTime).Round(time.Millisecond)
		reqPerSec := float64(completedJobs) / duration.Seconds()

		// Update message to show completion
		tracker.UpdateMessage(fmt.Sprintf("[%s] (completed)", moduleName))
		tracker.MarkAsDone()

		// Assign different colors to each bypass mode
		colorMap := map[string]text.Color{
			"dumb_check":        text.FgRed,
			"end_paths":         text.FgGreen,
			"case_substitution": text.FgBlue,
			"char_encode":       text.FgMagenta,
			"http_headers_url":  text.FgYellow,
			"mid_paths":         text.FgCyan,
		}

		// Log the completion message
		pc.ProgressWriter.Log(strings.Repeat("-", 100))
		pc.ProgressWriter.Log(fmt.Sprintf("[%s] Completed %d requests in %s (avg: %s req/s)",
			text.Colors{colorMap[moduleName]}.Sprintf("%-20s", moduleName),
			completedJobs,

			text.FgCyan.Sprintf("%-8s", duration),
			text.FgMagenta.Sprintf("%-8s", fmt.Sprintf("%.2f", reqPerSec))))
		pc.ProgressWriter.Log(strings.Repeat("-", 100))

	}
	pc.ActiveModules.Add(-1)
}

// Method to check if all modules are done
func (pc *ProgressCounter) AllModulesDone() bool {
	return pc.ActiveModules.Load() == 0
}

// Start the progress bar
func (pc *ProgressCounter) Start() {
	if !pc.Stopped.Swap(false) {
		go pc.ProgressWriter.Render()
	}
}

// Stop the progress bar
func (pc *ProgressCounter) Stop() {
	if !pc.Stopped.Swap(true) {
		pc.ProgressWriter.Stop()
	}
}
