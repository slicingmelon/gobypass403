package scanner

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jedib0t/go-pretty/v6/progress"
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
	pw.SetTrackerLength(40)
	pw.SetMessageLength(40)

	style := progress.StyleDefault
	style.Options.Separator = " "
	style.Options.DoneString = "completed"
	style.Options.ETAString = "eta"
	style.Visibility = progress.StyleVisibility{
		Percentage:     true,
		Speed:          true,
		Value:          true,
		ETA:            true,
		Time:           true,
		Tracker:        true,
		TrackerOverall: false,
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

	tracker := &progress.Tracker{
		Message: fmt.Sprintf("[%s] Processing %d requests", moduleName, totalJobs),
		Total:   int64(totalJobs),
		Units:   progress.UnitsDefault,
	}

	pc.trackers[moduleName+"_progress"] = tracker
	pc.pw.AppendTracker(tracker)
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
	pc.mu.RUnlock()

	if exists {
		atomic.StoreInt64(&stats.ActiveWorkers, totalWorkers)
		if tracker := pc.trackers[moduleName+"_workers"]; tracker != nil {
			tracker.SetValue(totalWorkers)
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
	pc.mu.RUnlock()

	if tracker != nil {
		tracker.MarkAsDone()
	}
	atomic.AddInt32(&pc.activeModules, -1)

	// If this was the last active module, stop the progress writer
	if atomic.LoadInt32(&pc.activeModules) == 0 {
		pc.Stop()
	}
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
