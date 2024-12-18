package scanner

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jedib0t/go-pretty/v6/progress"
	"github.com/jedib0t/go-pretty/v6/text"
)

type ProgressTracker struct {
	pw             progress.Writer
	moduleTrackers map[string]*progress.Tracker
	workerTracker  *progress.Tracker
	mu             sync.Mutex
	renderStarted  bool
}

// type ProgressTracker struct {
// 	trackers       map[string]*progress.Tracker
// 	moduleTrackers map[string]*progress.Tracker
// 	workerTracker  *progress.Tracker
// 	mu             sync.Mutex
// }

type ModuleStats struct {
	Total     int64
	Current   int64
	Workers   int
	URL       string
	StartTime time.Time
}

func NewProgressTracker(mode string, total int, targetURL string) *ProgressTracker {
	pw := progress.NewWriter()
	pw.SetOutputWriter(os.Stdout)
	pw.SetAutoStop(false)
	pw.SetTrackerLength(40)
	pw.SetUpdateFrequency(time.Millisecond * 100)

	// Custom style for the progress bars
	pw.SetStyle(progress.Style{
		Name: "bypass403",
		Chars: progress.StyleChars{
			BoxLeft:    "[",
			BoxRight:   "]",
			Finished:   "█",
			Unfinished: "░",
		},
		Colors: progress.StyleColors{
			Message: text.Colors{text.FgCyan},
			Error:   text.Colors{text.FgRed},
			Value:   text.Colors{text.FgYellow},
			Percent: text.Colors{text.FgGreen},
		},
	})
	pt := &ProgressTracker{
		pw:             pw,
		moduleTrackers: make(map[string]*progress.Tracker),
	}
	// Create module tracker
	moduleTracker := &progress.Tracker{
		Message: fmt.Sprintf("[%s] %s", mode, targetURL),
		Total:   int64(total),
		Units:   progress.UnitsDefault,
	}
	pt.moduleTrackers[mode] = moduleTracker
	pw.AppendTracker(moduleTracker)
	// Start rendering in background
	go pw.Render()
	return pt
}

func (pt *ProgressTracker) increment() {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	if pt.Cancelled {
		return
	}
	// Update module trackers
	for _, tracker := range pt.moduleTrackers {
		if !tracker.IsDone() {
			tracker.Increment(1)
		}
	}
	// Update worker tracker if exists
	if pt.workerTracker != nil {
		pt.workerTracker.Increment(1)
	}
}

func (pt *ProgressTracker) markAsCancelled() {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if !pt.Cancelled {
		pt.Cancelled = true
		for _, tracker := range pt.moduleTrackers {
			tracker.MarkAsErrored()
			tracker.UpdateMessage(fmt.Sprintf("%s [ERROR: Permanent error detected - Skipping]", tracker.Message))
		}
	}
}

func (pt *ProgressTracker) Stop() {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	// Mark all trackers as done
	for _, tracker := range pt.moduleTrackers {
		if !tracker.IsDone() {
			tracker.MarkAsDone()
		}
	}

	pt.pw.Stop()
}

func (pt *ProgressTracker) isCancelled() bool {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	return pt.Cancelled
}

func (pt *ProgressTracker) AddWorkerTracker(numWorkers int, totalJobs int) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.workerTracker = &progress.Tracker{
		Message: fmt.Sprintf("Workers [%d/%d]", numWorkers, numWorkers),
		Total:   int64(totalJobs),
		Units: progress.Units{
			Formatter: func(value int64) string {
				return fmt.Sprintf("%d/%d", value, totalJobs)
			},
		},
	}
	pt.pw.AppendTracker(pt.workerTracker)
}

// Update worker stats
func (pt *ProgressTracker) UpdateWorkerStats(processed int64, success int64, failed int64) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if pt.workerTracker != nil {
		pt.workerTracker.SetValue(processed)
		pt.workerTracker.UpdateMessage(fmt.Sprintf("Workers [✓%d ✗%d]", success, failed))
	}
}
