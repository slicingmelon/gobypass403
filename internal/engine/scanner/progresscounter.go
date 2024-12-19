package scanner

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jedib0t/go-pretty/v6/progress"
	"github.com/jedib0t/go-pretty/v6/text"
)

// const (
//     UnitsDefault = iota
//     UnitsBytes
//     UnitsPercentage
// )

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

	style := progress.StyleBlocks
	style.Colors = progress.StyleColors{
		Message: text.Colors{text.FgCyan},
		Error:   text.Colors{text.FgRed},
		Stats:   text.Colors{text.FgHiBlack},
		Time:    text.Colors{text.FgGreen},
		Value:   text.Colors{text.FgYellow},
		Speed:   text.Colors{text.FgMagenta},
		Percent: text.Colors{text.FgHiCyan},
	}
	style.Options.Separator = " │ "
	style.Options.DoneString = "✓"
	style.Options.ErrorString = "⨯"
	style.Options.SpeedSuffix = " req/s"

	// Configure visibility
	style.Visibility = progress.StyleVisibility{
		ETA:            false,
		ETAOverall:     false,
		Percentage:     false, // Don't show percentage for workers
		Speed:          true,
		Time:           true,
		Tracker:        true,
		TrackerOverall: false,
		Value:          true, // Show the actual worker count
	}

	pw.SetStyle(style)
	pw.SetTrackerPosition(progress.PositionRight)
	pw.SetOutputWriter(os.Stdout)
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
		Message: fmt.Sprintf("[%s]", moduleName),
		Total:   int64(totalJobs),
		Units:   progress.UnitsDefault,
	}
	pc.trackers[moduleName+"_progress"] = tracker
	pc.pw.AppendTracker(tracker)

	// Worker tracker
	workerTracker := &progress.Tracker{
		Message: fmt.Sprintf("[%s Status]", moduleName),
		Total:   100,
		Units:   progress.UnitsDefault,
	}
	pc.trackers[moduleName+"_workers"] = workerTracker
	pc.pw.AppendTracker(workerTracker)
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
	workerTracker := pc.trackers[moduleName+"_workers"]
	pc.mu.RUnlock()

	if exists && workerTracker != nil {
		atomic.StoreInt64(&stats.ActiveWorkers, totalWorkers)
		workerTracker.SetValue(totalWorkers)

		if totalWorkers > 0 {
			message := fmt.Sprintf("[%s] %s",
				text.FgCyan.Sprint(moduleName),
				text.FgYellow.Sprintf("Processing (%d workers)", totalWorkers))
			workerTracker.UpdateMessage(message)
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
	workerTracker := pc.trackers[moduleName+"_workers"]
	stats := pc.moduleStats[moduleName]
	pc.mu.RUnlock()

	if tracker != nil {
		tracker.MarkAsDone()
	}

	if workerTracker != nil {
		completedJobs := atomic.LoadInt64(&stats.CompletedJobs)
		duration := time.Since(stats.StartTime).Round(time.Millisecond)

		message := fmt.Sprintf("[%s] %s",
			text.FgCyan.Sprint(moduleName),
			text.FgGreen.Sprintf("Completed %d jobs in %s", completedJobs, duration))

		workerTracker.UpdateMessage(message)
		workerTracker.SetValue(100) // Set to 100% complete
		workerTracker.MarkAsDone()
	}

	atomic.AddInt32(&pc.activeModules, -1)
}

// Add a new method to check if all modules are done
func (pc *ProgressCounter) AllModulesDone() bool {
	return atomic.LoadInt32(&pc.activeModules) == 0
}

func (pc *ProgressCounter) Start() {
	// Start rendering in background
	go pc.pw.Render()
}

func (pc *ProgressCounter) Stop() {
	if !pc.stopped.Swap(true) { // Only stop once
		pc.pw.Stop()
	}
}
