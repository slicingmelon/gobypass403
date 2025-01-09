package scanner

import (
	"fmt"
	"testing"
	"time"

	"github.com/jedib0t/go-pretty/v6/progress"
)

func TestProgressCounterStyles(t *testing.T) {
	styles := map[string]*ProgressCounter{
		"Default": NewProgressCounterDefault(),
		"Blocks":  NewProgressCounterBlocks(),
		"Circle":  NewProgressCounterCircle(),
		"Rhombus": NewProgressCounterRhombus(),
	}
	testModules := []struct {
		name    string
		jobs    int
		workers int64
		success float64
	}{
		{"dumb_check", 10, 2, 0.8},
		{"case_substitution", 20, 4, 0.9},
		{"mid_paths", 30, 6, 0.95},
	}
	for styleName, pc := range styles {
		t.Run(styleName, func(t *testing.T) {
			pc.Start()
			defer pc.Stop()
			for _, module := range testModules {
				simulateModuleProgress(pc, module.name, module.jobs, module.workers, module.success)
				time.Sleep(time.Second)
			}
			for !pc.AllModulesDone() {
				time.Sleep(100 * time.Millisecond)
			}
			time.Sleep(time.Second)
		})
	}
}

func TestProgressCounterBasic(t *testing.T) {
	pc := NewProgressCounter()
	pc.Start()
	defer pc.Stop()
	moduleName := "test_module"
	pc.StartModule(moduleName, 10, "http://example.com")
	for i := 0; i < 10; i++ {
		pc.UpdateWorkerStats(moduleName, 2)
		pc.IncrementProgress(moduleName, true)
		time.Sleep(100 * time.Millisecond)
	}
	pc.MarkModuleAsDone(moduleName)
	if !pc.AllModulesDone() {
		t.Error("Expected all modules to be done")
	}
}
func TestProgressCounterConcurrent(t *testing.T) {
	pc := NewProgressCounter()
	pc.Start()
	defer pc.Stop()
	modules := []string{"module1", "module2", "module3"}
	for _, module := range modules {
		go func(name string) {
			pc.StartModule(name, 5, "http://example.com")
			for i := 0; i < 5; i++ {
				pc.UpdateWorkerStats(name, 1)
				pc.IncrementProgress(name, true)
				time.Sleep(200 * time.Millisecond)
			}
			pc.MarkModuleAsDone(name)
		}(module)
	}
	timeout := time.After(5 * time.Second)
	for !pc.AllModulesDone() {
		select {
		case <-timeout:
			t.Fatal("Test timed out")
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func TestProgressCounterStressTest(t *testing.T) {
	pc := NewProgressCounter()
	pc.Start()
	defer pc.Stop()
	t.Log("Starting stress test")
	simulateModuleProgress(pc, "stress_test", 10000, 500, 1.0)
	for !pc.AllModulesDone() {
		time.Sleep(50 * time.Millisecond)
	}
}

func TestProgressCounterEdgeCases(t *testing.T) {
	pc := NewProgressCounter()
	pc.Start()
	defer pc.Stop()
	testCases := []struct {
		name      string
		jobs      int
		workers   int64
		operation func(pc *ProgressCounter, name string)
	}{
		{
			name:    "zero_jobs",
			jobs:    0,
			workers: 1,
			operation: func(pc *ProgressCounter, name string) {
				pc.StartModule(name, 0, "http://example.com")
				pc.MarkModuleAsDone(name)
			},
		},
		{
			name:    "many_workers",
			jobs:    5,
			workers: 100,
			operation: func(pc *ProgressCounter, name string) {
				pc.StartModule(name, 5, "http://example.com")
				pc.UpdateWorkerStats(name, 100)
				for i := 0; i < 5; i++ {
					pc.IncrementProgress(name, true)
				}
				pc.MarkModuleAsDone(name)
			},
		},
		{
			name:    "rapid_updates",
			jobs:    100,
			workers: 1,
			operation: func(pc *ProgressCounter, name string) {
				pc.StartModule(name, 100, "http://example.com")
				for i := 0; i < 100; i++ {
					pc.IncrementProgress(name, true)
				}
				pc.MarkModuleAsDone(name)
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.operation(pc, tc.name)
		})
	}
}

func TestProgressCounterStress(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}
	pc := NewProgressCounter()
	pc.Start()
	defer pc.Stop()
	const (
		numModules        = 10
		jobsPerModule     = 1000
		concurrentWorkers = 50
	)
	done := make(chan bool)
	for i := 0; i < numModules; i++ {
		go func(moduleID int) {
			moduleName := fmt.Sprintf("stress_module_%d", moduleID)
			pc.StartModule(moduleName, jobsPerModule, "http://example.com")
			for j := 0; j < jobsPerModule; j++ {
				pc.UpdateWorkerStats(moduleName, concurrentWorkers)
				pc.IncrementProgress(moduleName, true)
				time.Sleep(time.Millisecond)
			}
			pc.MarkModuleAsDone(moduleName)
			done <- true
		}(i)
	}
	for i := 0; i < numModules; i++ {
		<-done
	}
}

// Helper functions for creating different progress counter styles
func NewProgressCounterDefault() *ProgressCounter {
	pw := progress.NewWriter()
	pw.SetUpdateFrequency(100 * time.Millisecond)
	pw.SetTrackerLength(45)
	pw.SetMessageLength(45)
	pw.SetStyle(progress.StyleDefault)
	pw.SetTrackerPosition(progress.PositionRight)
	return &ProgressCounter{
		pw:          pw,
		trackers:    make(map[string]*progress.Tracker),
		moduleStats: make(map[string]*ModuleStats),
	}
}

func NewProgressCounterBlocks() *ProgressCounter {
	pw := progress.NewWriter()
	pw.SetUpdateFrequency(100 * time.Millisecond)
	pw.SetTrackerLength(45)
	pw.SetMessageLength(45)

	style := progress.StyleBlocks
	style.Options.Separator = " │ "
	style.Options.DoneString = "✔"
	style.Options.ErrorString = "⨯"

	pw.SetStyle(style)
	pw.SetTrackerPosition(progress.PositionRight)
	return &ProgressCounter{
		pw:          pw,
		trackers:    make(map[string]*progress.Tracker),
		moduleStats: make(map[string]*ModuleStats),
	}
}

func NewProgressCounterCircle() *ProgressCounter {
	pw := progress.NewWriter()
	pw.SetUpdateFrequency(100 * time.Millisecond)
	pw.SetTrackerLength(45)
	pw.SetMessageLength(45)

	style := progress.StyleCircle
	style.Options.Separator = " ⦾ "
	style.Options.DoneString = "●"
	style.Options.ErrorString = "○"

	pw.SetStyle(style)
	pw.SetTrackerPosition(progress.PositionRight)
	return &ProgressCounter{
		pw:          pw,
		trackers:    make(map[string]*progress.Tracker),
		moduleStats: make(map[string]*ModuleStats),
	}
}

func NewProgressCounterRhombus() *ProgressCounter {
	pw := progress.NewWriter()
	pw.SetUpdateFrequency(100 * time.Millisecond)
	pw.SetTrackerLength(45)
	pw.SetMessageLength(45)

	style := progress.StyleRhombus
	style.Options.Separator = " ◊ "
	style.Options.DoneString = "◆"
	style.Options.ErrorString = "◇"

	pw.SetStyle(style)
	pw.SetTrackerPosition(progress.PositionRight)
	return &ProgressCounter{
		pw:          pw,
		trackers:    make(map[string]*progress.Tracker),
		moduleStats: make(map[string]*ModuleStats),
	}
}

// Helper function to simulate module progress
func simulateModuleProgress(pc *ProgressCounter, moduleName string, totalJobs int, workers int64, successRate float64) {
	pc.StartModule(moduleName, totalJobs, "https://test.example.com/path")

	go func() {
		for i := int64(0); i <= workers; i += workers / 4 {
			pc.UpdateWorkerStats(moduleName, i)
			time.Sleep(100 * time.Millisecond)
		}
	}()

	go func() {
		for i := 0; i < totalJobs; i++ {
			success := float64(i)/float64(totalJobs) < successRate
			pc.IncrementProgress(moduleName, success)
			time.Sleep(50 * time.Millisecond)
		}

		pc.UpdateWorkerStats(moduleName, 0)
		pc.MarkModuleAsDone(moduleName)
	}()
}
