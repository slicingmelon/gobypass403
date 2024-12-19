package scanner

import (
	"fmt"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jedib0t/go-pretty/v6/progress"
	"github.com/jedib0t/go-pretty/v6/text"
)

func TestProgressCounter(t *testing.T) {
	// Create a new progress counter
	pc := NewProgressCounter()

	// Start the progress counter
	pc.Start()
	defer pc.Stop()

	// Simulate multiple modules with different workloads
	testCases := []struct {
		moduleName  string
		totalJobs   int
		workers     int64
		successRate float64 // percentage of successful jobs
	}{
		{"dumb_check", 1, 1, 1.0},
		{"case_substitution", 11, 5, 0.9},
		{"char_encode", 33, 10, 0.95},
		{"mid_paths", 200, 100, 0.85},
	}

	// Process each test case
	for _, tc := range testCases {
		t.Logf("Starting module: %s\n", tc.moduleName)
		simulateModuleProgress(pc, tc.moduleName, tc.totalJobs, tc.workers, tc.successRate)
		time.Sleep(500 * time.Millisecond) // Wait between modules
	}

	// Wait for all modules to complete
	for !pc.AllModulesDone() {
		time.Sleep(100 * time.Millisecond)
	}
}

// TestProgressCounterStressTest simulates high concurrency scenarios
func TestProgressCounterStressTest(t *testing.T) {
	pc := NewProgressCounter()
	pc.Start()
	defer pc.Stop()

	// Simulate a large module with rapid updates
	t.Log("Starting stress test")
	//text.FgGreen.Sprint("Starting stress test")
	simulateModuleProgress(pc, "stress_test", 10000, 500, 1.0)

	// Wait for completion
	for !pc.AllModulesDone() {
		time.Sleep(50 * time.Millisecond)
	}
}

// TestProgressCounterEdgeCases tests various edge cases
func TestProgressCounterEdgeCases(t *testing.T) {
	pc := NewProgressCounter()
	pc.Start()
	defer pc.Stop()

	testCases := []struct {
		name      string
		totalJobs int
		workers   int64
	}{
		{"empty_module", 0, 0},
		{"single_job", 1, 1},
		{"many_workers_few_jobs", 10, 100},
		{"negative_jobs", -1, 1},
		{"zero_workers_many_jobs", 1000, 0},
		{"max_workers", 1000, 1000},
		{"rapid_completion", 100, 50},
		{"worker_fluctuation", 500, 20},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing edge case: %s\n", tc.name)
			simulateModuleProgress(pc, tc.name, tc.totalJobs, tc.workers, 1.0)
		})
		time.Sleep(200 * time.Millisecond) // Wait between test cases
	}

	// Wait for all modules to complete
	for !pc.AllModulesDone() {
		time.Sleep(50 * time.Millisecond)
	}
}

func getMessage(idx int64, units *progress.Units) string {
	var message string
	switch units {
	case &progress.UnitsBytes:
		message = fmt.Sprintf("Downloading File    #%3d", idx)
	case &progress.UnitsCurrencyDollar, &progress.UnitsCurrencyEuro, &progress.UnitsCurrencyPound:
		message = fmt.Sprintf("Transferring Amount #%3d", idx)
	default:
		message = fmt.Sprintf("Calculating Total   #%3d", idx)
	}
	return message
}

func getUnits(idx int64) *progress.Units {
	var units *progress.Units
	switch {
	case idx%5 == 0:
		units = &progress.UnitsCurrencyPound
	case idx%4 == 0:
		units = &progress.UnitsCurrencyDollar
	case idx%3 == 0:
		units = &progress.UnitsBytes
	default:
		units = &progress.UnitsDefault
	}
	return units
}

func trackSomething(pw progress.Writer, idx int64, updateMessage bool) {
	total := idx * idx * idx * 250
	incrementPerCycle := idx * int64(*flagNumTrackers) * 250

	units := getUnits(idx)
	message := getMessage(idx, units)
	tracker := progress.Tracker{
		DeferStart:         *flagRandomDefer && rand.Float64() < 0.5,
		Message:            message,
		RemoveOnCompletion: *flagRandomRemove && rand.Float64() < 0.25,
		Total:              total,
		Units:              *units,
	}
	if idx == int64(*flagNumTrackers) {
		tracker.Total = 0
	}

	pw.AppendTracker(&tracker)

	if tracker.DeferStart {
		time.Sleep(3 * time.Second)
		tracker.Start()
	}

	ticker := time.Tick(time.Millisecond * 500)
	updateTicker := time.Tick(time.Millisecond * 250)
	for !tracker.IsDone() {
		select {
		case <-ticker:
			tracker.Increment(incrementPerCycle)
			if idx == int64(*flagNumTrackers) && tracker.Value() >= total {
				tracker.MarkAsDone()
			} else if *flagRandomFail && rand.Float64() < 0.1 {
				tracker.MarkAsErrored()
			}
			pw.SetPinnedMessages(
				fmt.Sprintf(">> Current Time: %-32s", time.Now().Format(time.RFC3339)),
				fmt.Sprintf(">>   Total Time: %-32s", time.Since(timeStart).Round(time.Millisecond)),
			)
		case <-updateTicker:
			if updateMessage {
				rndIdx := rand.Intn(len(messageColors))
				if rndIdx == len(messageColors) {
					rndIdx--
				}
				tracker.UpdateMessage(messageColors[rndIdx].Sprint(message))
			}
		}
	}
}

func (pc *ProgressCounter) MarkModuleAsDoneTest(moduleName string) {
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
		duration := time.Since(stats.StartTime).Round(time.Millisecond)

		// Assign random colors to each bypass mode
		colorMap := map[string]text.Color{
			"dumb_check":        text.FgRed,
			"end_paths":         text.FgGreen,
			"case_substitution": text.FgBlue,
			"char_encode":       text.FgMagenta,
			"http_headers_url":  text.FgYellow,
			"mid_paths":         text.FgCyan,
			// Add more mappings as needed
		}

		// Use the color for the module name
		moduleColor := colorMap[moduleName]

		// Update the completion message for better alignment and readability
		message := fmt.Sprintf("[%s] Completed %d requests in %s (avg: %s req/s)",
			moduleColor.Sprintf("%-20s", moduleName),
			completedJobs,
			text.FgCyan.Sprintf("%-8s", duration),
			text.FgMagenta.Sprintf("%-8s", fmt.Sprintf("%.2f", float64(completedJobs)/duration.Seconds())))

		// Log the final result with a separator
		pc.pw.Log("---------------------------------------")
		pc.pw.Log(message)
		pc.pw.Log("----------------------------------------")
	}

	atomic.AddInt32(&pc.activeModules, -1)
}

// Helper function to simulate a module's progress with colored output
func simulateModuleProgress(pc *ProgressCounter, moduleName string, totalJobs int, workers int64, successRate float64) {
	// Initialize module
	pc.StartModule(moduleName, totalJobs, "https://test.example.com/path")

	// Simulate worker count updates
	go func() {
		for i := int64(0); i <= workers; i += workers / 4 {
			pc.UpdateWorkerStats(moduleName, i)
			time.Sleep(100 * time.Millisecond)
		}
	}()

	// Simulate job processing
	go func() {
		for i := 0; i < totalJobs; i++ {
			success := float64(i)/float64(totalJobs) < successRate
			pc.IncrementProgress(moduleName, success)
			time.Sleep(50 * time.Millisecond) // Simulate processing time
		}

		// Update final worker count and mark as done
		pc.UpdateWorkerStats(moduleName, 0)
		moduLeName := "mid_paths"
		pc.MarkModuleAsDoneTest(moduLeName)
	}()
}
