package scanner

import (
	"fmt"
	"testing"
	"time"

	"github.com/jedib0t/go-pretty/v6/progress"
)

// Helper function to simulate a module's progress with a given style
func simulateProgressWithStyle(t *testing.T, style progress.Style) {
	pw := progress.NewWriter()
	pw.SetUpdateFrequency(100 * time.Millisecond)
	pw.SetTrackerLength(45)
	pw.SetMessageLength(45)
	pw.SetStyle(style)
	pw.SetTrackerPosition(progress.PositionRight)

	pc := &ProgressCounter{
		pw:          pw,
		trackers:    make(map[string]*progress.Tracker),
		moduleStats: make(map[string]*ModuleStats),
	}

	pc.Start()
	defer pc.Stop()

	// Simulate a single module with a few jobs
	moduleName := "test_module"
	pc.StartModule(moduleName, 10, "http://example.com")

	for i := 0; i < 10; i++ {
		pc.UpdateWorkerStats(moduleName, 2)
		pc.IncrementProgress(moduleName, true)
		time.Sleep(100 * time.Millisecond)
	}

	pc.MarkModuleAsDone(moduleName)

	// Wait for all modules to complete
	for !pc.AllModulesDone() {
		time.Sleep(100 * time.Millisecond)
	}
}

func TestProgressCounterStyle2s(t *testing.T) {
	styles := map[string]progress.Style{
		"Default": progress.StyleDefault,
		"Blocks":  progress.StyleBlocks,
		"Circle":  progress.StyleCircle,
		"Rhombus": progress.StyleRhombus,
	}

	for styleName, style := range styles {
		t.Run(styleName, func(t *testing.T) {
			fmt.Printf("Testing style: %s\n", styleName)
			simulateProgressWithStyle(t, style)
		})
	}
}
