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
	pw.SetAutoStop(true)
	pw.SetNumTrackersExpected(1)
	pw.SetSortBy(progress.SortByPercentDsc)
	pw.SetUpdateFrequency(100 * time.Millisecond)
	pw.SetTrackerLength(45)
	pw.SetMessageLength(45)
	pw.SetStyle(style)
	pw.SetTrackerPosition(progress.PositionRight)

	style.Visibility.ETA = true
	style.Visibility.ETAOverall = true
	style.Visibility.Percentage = true
	style.Visibility.Speed = true
	style.Visibility.SpeedOverall = true
	style.Visibility.Time = true
	style.Visibility.Value = true
	style.Visibility.Pinned = true

	style.Options.PercentFormat = "%4.1f%%"

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
		time.Sleep(300 * time.Millisecond)
	}

	pc.MarkModuleAsDone(moduleName)

	// Wait for all modules to complete
	for !pc.AllModulesDone() {
		time.Sleep(100 * time.Millisecond)
	}
}

func TestProgressCounterAllStyles(t *testing.T) {
	// Define all available styles with custom configurations
	styles := map[string]progress.Style{
		"Default": {
			Name:       "StyleDefault",
			Chars:      progress.StyleCharsDefault,
			Colors:     progress.StyleColorsExample,
			Options:    customOptions("[", "]", "#", ".", "done!", "fail!"),
			Visibility: progress.StyleVisibilityDefault,
		},
		"Blocks": {
			Name:       "StyleBlocks",
			Chars:      progress.StyleCharsBlocks,
			Colors:     progress.StyleColorsExample,
			Options:    customOptions("║", "║", "█", "��", "✔", "✘"),
			Visibility: progress.StyleVisibilityDefault,
		},
		"Circle": {
			Name:       "StyleCircle",
			Chars:      progress.StyleCharsCircle,
			Colors:     progress.StyleColorsExample,
			Options:    customOptions("⦾", "⦿", "●", "○", "●", "����"),
			Visibility: progress.StyleVisibilityDefault,
		},
		"Rhombus": {
			Name:       "StyleRhombus",
			Chars:      progress.StyleCharsRhombus,
			Colors:     progress.StyleColorsExample,
			Options:    customOptions("◊", "◊", "◆", "◇", "◆", "◇"),
			Visibility: progress.StyleVisibilityDefault,
		},
		"Braille": {
			Name:       "StyleBraille",
			Chars:      customChars("⣷", "⣯", "⣟", "⡿", "⢿", "⣻", "⣽", "⣾"),
			Colors:     progress.StyleColorsExample,
			Options:    customOptions("", "", "⠿", "⠄", "✓", "✗"),
			Visibility: progress.StyleVisibilityDefault,
		},
		"Moon": {
			Name:       "StyleMoon",
			Chars:      customChars("🌑", "🌒", "🌓", "🌔", "🌕", "🌖", "🌗", "🌘"),
			Colors:     progress.StyleColorsExample,
			Options:    customOptions("", "", "🌕", "🌑", "✨", "💫"),
			Visibility: progress.StyleVisibilityDefault,
		},
	}

	for styleName, style := range styles {
		t.Run(styleName, func(t *testing.T) {
			fmt.Println()
			fmt.Printf("Testing style: %s\n", styleName)
			simulateProgressWithStyle(t, style)
			time.Sleep(time.Second) // Pause between styles for better visibility
		})
	}
}

// Helper function to create custom style options
func customOptions(boxLeft, boxRight, finished, unfinished, doneString, errorString string) progress.StyleOptions {
	opts := progress.StyleOptionsDefault
	opts.Separator = " │ "
	opts.DoneString = doneString
	opts.ErrorString = errorString
	return opts
}

// Helper function to create custom chars for styles
func customChars(chars ...string) progress.StyleChars {
	return progress.StyleChars{
		BoxLeft:    chars[0],
		BoxRight:   chars[1],
		Finished:   chars[2],
		Finished25: chars[3],
		Finished50: chars[4],
		Finished75: chars[5],
		Unfinished: chars[6],
	}
}

func TestProgressCounterMultipleRandomBars(t *testing.T) {
	pw := progress.NewWriter()
	pw.SetAutoStop(false)
	pw.SetMessageLength(35)
	pw.SetNumTrackersExpected(10)
	pw.SetSortBy(progress.SortByPercentDsc)
	pw.SetStyle(progress.StyleDefault)
	pw.SetTrackerLength(45)
	pw.SetTrackerPosition(progress.PositionRight)
	pw.SetUpdateFrequency(time.Millisecond * 100)

	pw.Style().Colors = progress.StyleColorsExample
	pw.Style().Options.PercentFormat = "%4.1f%%"
	pw.Style().Visibility.ETA = true
	pw.Style().Visibility.Percentage = true
	pw.Style().Visibility.Speed = true
	pw.Style().Visibility.Time = true
	pw.Style().Visibility.Value = true

	// Start rendering before adding trackers
	go pw.Render()

	tasks := []struct {
		name  string
		total int64
		speed time.Duration
	}{
		{"Quick Bypass Check", 100, 50 * time.Millisecond},
		{"Final Verification", 400, 40 * time.Millisecond},
		{"Header Manipulation", 1000, 30 * time.Millisecond},
		{"Protocol Test", 300, 25 * time.Millisecond},
		{"Deep Scan", 1500, 20 * time.Millisecond},
		{"Full Path Scan", 2000, 15 * time.Millisecond},
		{"Auth Bypass Check", 50, 30 * time.Millisecond},
		{"Path Traversal Test", 150, 35 * time.Millisecond},
		{"Quick Headers", 150, 25 * time.Millisecond},
		{"WAF Detection", 200, 45 * time.Millisecond},
	}

	for _, task := range tasks {
		go func(t struct {
			name  string
			total int64
			speed time.Duration
		}) {
			tracker := &progress.Tracker{
				Message: t.name,
				Total:   t.total,
				Units:   progress.UnitsDefault,
			}
			pw.AppendTracker(tracker)

			ticker := time.Tick(t.speed)
			for !tracker.IsDone() {
				select {
				case <-ticker:
					tracker.Increment(1)
					if tracker.Value() >= t.total {
						tracker.MarkAsDone()
					}
				}
			}
		}(task)
	}

	// Wait for trackers to become active and complete
	time.Sleep(time.Second)
	for pw.IsRenderInProgress() {
		if pw.LengthActive() == 0 {
			pw.Stop()
		}
		time.Sleep(100 * time.Millisecond)
	}
}
