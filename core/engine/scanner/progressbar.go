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

// ProgressBarWrapper wraps the fortio progressbar to respect an enabled flag
type ProgressBarWrapper struct {
	bar         *progressbar.Bar
	enabledFlag *atomic.Bool
}

// NewProgressBarWrapper creates a new progress bar wrapper
func NewProgressBarWrapper(cfg progressbar.Config, enabledFlag *atomic.Bool) *ProgressBarWrapper {
	var bar *progressbar.Bar
	if enabledFlag.Load() {
		bar = cfg.NewBar()
	}
	return &ProgressBarWrapper{
		bar:         bar,
		enabledFlag: enabledFlag,
	}
}

// Progress updates the progress percentage
func (p *ProgressBarWrapper) Progress(percentage float64) {
	if p.enabledFlag.Load() && p.bar != nil {
		p.bar.Progress(percentage)
	}
}

// WriteAbove writes text above the progress bar
func (p *ProgressBarWrapper) WriteAbove(text string) {
	if p.enabledFlag.Load() && p.bar != nil {
		p.bar.WriteAbove(text)
	}
}

// End finishes the progress bar
func (p *ProgressBarWrapper) End() {
	if p.enabledFlag.Load() && p.bar != nil {
		p.bar.End()
	}
}
