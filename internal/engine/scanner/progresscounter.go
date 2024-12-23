package scanner

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jedib0t/go-pretty/v6/progress"
	"github.com/jedib0t/go-pretty/v6/text"
)

type ModuleStats struct {
	TotalJobs      int64
	CompletedJobs  int64
	SuccessfulJobs int64
	FailedJobs     int64
	ActiveWorkers  int64
	StartTime      time.Time
}

type ProgressCounter struct {
	pw            progress.Writer
	trackers      map[string]*progress.Tracker
	moduleStats   map[string]*ModuleStats
	mu            sync.RWMutex
	activeModules int32
	stopped       atomic.Bool // Add this
}

func NewProgressCounter() *ProgressCounter {
	pw := progress.NewWriter()
	pw.SetUpdateFrequency(100 * time.Millisecond)
	pw.SetTrackerLength(45)
	pw.SetMessageLength(45)
	pw.SetAutoStop(true)
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
		// Add pinned message color
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
		// Add snip indicator for long messages
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
		Pinned:         true, // Enable pinned messages
	}
	pw.SetStyle(style)
	pw.SetTrackerPosition(progress.PositionRight)
	return &ProgressCounter{
		pw:          pw,
		trackers:    make(map[string]*progress.Tracker),
		moduleStats: make(map[string]*ModuleStats),
	}
}

func (pc *ProgressCounter) StartModule(moduleName string, totalJobs int, targetURL string) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	atomic.AddInt32(&pc.activeModules, 1)
	pc.moduleStats[moduleName] = &ModuleStats{
		TotalJobs: int64(totalJobs),
		StartTime: time.Now(),
	}
	// Main progress tracker
	tracker := &progress.Tracker{
		Message: fmt.Sprintf("[%s] (0 workers)", moduleName),
		Total:   int64(totalJobs),
		Units:   progress.UnitsDefault,
	}
	pc.trackers[moduleName+"_progress"] = tracker
	pc.pw.AppendTracker(tracker)
	// Set initial pinned messages
	pc.pw.SetPinnedMessages(
		text.FgCyan.Sprintf("Target URL: %s", targetURL),
		text.FgYellow.Sprintf("Active Module: %s", moduleName),
		text.FgGreen.Sprintf("Started: %s", time.Now().Format("15:04:05")),
		text.FgHiBlack.Sprintf("Total Jobs: %d", totalJobs),
	)
	// Start rendering in the background
	go pc.pw.Render()

}

func (pc *ProgressCounter) addTracker(id, message string, total int64) {
	tracker := &progress.Tracker{
		Message: message,
		Total:   total,
		Units:   progress.UnitsDefault,
	}
	pc.trackers[id] = tracker
	pc.pw.AppendTracker(tracker)
}

func (pc *ProgressCounter) UpdateWorkerStats(moduleName string, totalWorkers int64) {
	pc.mu.RLock()
	stats, exists := pc.moduleStats[moduleName]
	tracker := pc.trackers[moduleName+"_progress"]
	pc.mu.RUnlock()

	if exists {
		atomic.StoreInt64(&stats.ActiveWorkers, totalWorkers)

		// Update the tracker message to include worker count
		if tracker != nil {
			newMessage := fmt.Sprintf("[%s] (%d workers)", moduleName, totalWorkers)
			tracker.UpdateMessage(newMessage)
		}
	}
}

func (pc *ProgressCounter) IncrementProgress(moduleName string, success bool) {
	pc.mu.RLock()
	stats, exists := pc.moduleStats[moduleName]
	tracker := pc.trackers[moduleName+"_progress"]
	pc.mu.RUnlock()

	if exists && tracker != nil {
		atomic.AddInt64(&stats.CompletedJobs, 1)
		if success {
			atomic.AddInt64(&stats.SuccessfulJobs, 1)
		} else {
			atomic.AddInt64(&stats.FailedJobs, 1)
		}
		tracker.Increment(1)
	}
}

func (pc *ProgressCounter) MarkModuleAsDone(moduleName string) {
	pc.mu.RLock()
	tracker := pc.trackers[moduleName+"_progress"]
	stats := pc.moduleStats[moduleName]
	pc.mu.RUnlock()
	if tracker != nil {
		// Update message to show completion instead of worker count
		tracker.UpdateMessage(fmt.Sprintf("[%s] (completed)", moduleName))
		tracker.MarkAsDone()
	}
	if stats != nil {
		completedJobs := atomic.LoadInt64(&stats.CompletedJobs)
		successfulJobs := atomic.LoadInt64(&stats.SuccessfulJobs)
		failedJobs := atomic.LoadInt64(&stats.FailedJobs)
		duration := time.Since(stats.StartTime).Round(time.Millisecond)
		reqPerSec := float64(completedJobs) / duration.Seconds()
		// Update pinned messages with completion stats
		pc.pw.SetPinnedMessages(
			text.FgCyan.Sprintf("Module: %s (Completed)", moduleName),
			text.FgGreen.Sprintf("Success: %d/%d (%.1f%%)",
				successfulJobs, completedJobs,
				float64(successfulJobs)/float64(completedJobs)*100),
			text.FgRed.Sprintf("Failed: %d requests", failedJobs),
			text.FgMagenta.Sprintf("Speed: %.2f req/s", reqPerSec),
			text.FgHiBlack.Sprintf("Duration: %s", duration),
		)
		// Assign different colors to each bypass mode
		colorMap := map[string]text.Color{
			"dumb_check":        text.FgRed,
			"end_paths":         text.FgGreen,
			"case_substitution": text.FgBlue,
			"char_encode":       text.FgMagenta,
			"http_headers_url":  text.FgYellow,
			"mid_paths":         text.FgCyan,
		}
		moduleColor := colorMap[moduleName]
		message := fmt.Sprintf("[%s] Completed %d requests in %s (avg: %s req/s)",
			moduleColor.Sprintf("%-20s", moduleName),
			completedJobs,
			text.FgCyan.Sprintf("%-8s", duration),
			text.FgMagenta.Sprintf("%-8s", fmt.Sprintf("%.2f", reqPerSec)))
		pc.pw.Log("----------------------------------------")
		pc.pw.Log(message)
		pc.pw.Log("----------------------------------------")
	}
	atomic.AddInt32(&pc.activeModules, -1)
}

// Add a new method to check if all modules are done
func (pc *ProgressCounter) AllModulesDone() bool {
	return atomic.LoadInt32(&pc.activeModules) == 0
}

func (pc *ProgressCounter) Start() {
	if !pc.stopped.Swap(false) {
		go pc.pw.Render()
	}
}

func (pc *ProgressCounter) Stop() {
	if !pc.stopped.Swap(true) {
		pc.pw.Stop()
	}
}
