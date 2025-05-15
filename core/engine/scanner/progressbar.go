/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package scanner

import (
	"sync/atomic"

	"fortio.org/progressbar"
)

// ProgressBar wraps the fortio progressbar to respect an enabled flag
type ProgressBar struct {
	bar         *progressbar.Bar
	enabledFlag *atomic.Bool
}

// NewProgressBar creates a new progress bar wrapper with the specified configuration
func NewProgressBar(prefix string, color string, extraLines int, enabledFlag *atomic.Bool) *ProgressBar {
	var bar *progressbar.Bar
	if enabledFlag.Load() {
		cfg := progressbar.DefaultConfig()
		cfg.Prefix = prefix
		cfg.UseColors = true
		cfg.ExtraLines = extraLines
		cfg.Color = color
		bar = cfg.NewBar()
	}
	return &ProgressBar{
		bar:         bar,
		enabledFlag: enabledFlag,
	}
}

// Progress updates the progress percentage
func (p *ProgressBar) Progress(percentage float64) {
	if p.enabledFlag.Load() && p.bar != nil {
		p.bar.Progress(percentage)
	}
}

// WriteAbove writes text above the progress bar
func (p *ProgressBar) WriteAbove(text string) {
	if p.enabledFlag.Load() && p.bar != nil {
		p.bar.WriteAbove(text)
	}
}

// End finishes the progress bar
func (p *ProgressBar) End() {
	if p.enabledFlag.Load() && p.bar != nil {
		p.bar.End()
	}
}
