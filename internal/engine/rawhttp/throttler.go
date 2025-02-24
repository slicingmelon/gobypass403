package rawhttp

import (
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

type ThrottleConfig struct {
	BaseRequestDelay        time.Duration
	MaxRequestDelay         time.Duration
	ExponentialRequestDelay float64 // Exponential request delay
	RequestDelayJitter      int     // For random delay, percentage of variation (0-100)
	ThrottleOnStatusCodes   []int   // Status codes that trigger throttling
}

// Throttler handles request rate limiting
type Throttler struct {
	config       atomic.Pointer[ThrottleConfig]
	counter      atomic.Int32 // Counts consecutive throttled responses
	lastDelay    atomic.Int64 // Last calculated delay in nanoseconds
	isThrottling atomic.Bool  // Indicates if auto throttling is currently active
	mu           sync.RWMutex
}

// DefaultThrottleConfig returns sensible defaults
func DefaultThrottleConfig() *ThrottleConfig {
	return &ThrottleConfig{
		BaseRequestDelay:        200 * time.Millisecond,
		MaxRequestDelay:         5000 * time.Millisecond,
		RequestDelayJitter:      20,  // 20% of the base request delay
		ExponentialRequestDelay: 2.0, // Each throttle doubles the delay
		ThrottleOnStatusCodes:   []int{429, 503, 507},
	}
}

// NewThrottler creates a new throttler instance
func NewThrottler(config *ThrottleConfig) *Throttler {
	t := &Throttler{}
	if config == nil {
		config = DefaultThrottleConfig()
	}
	t.config.Store(config)
	return t
}

// IsThrottableRespCode checks if we should throttle based on the resp status code
func (t *Throttler) IsThrottableRespCode(statusCode int) bool {
	if t == nil {
		return false
	}

	config := t.config.Load()
	if matchStatusCodes(statusCode, config.ThrottleOnStatusCodes) {
		t.counter.Add(1)
		return true
	}
	return false
}

// GetCurrentThrottleRate calculates the next delay based on config and attempts
func (t *Throttler) GetCurrentThrottleRate() time.Duration {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.config.Load() == nil || !t.isThrottling.Load() {
		return 0
	}

	config := t.config.Load()
	baseDelay := config.BaseRequestDelay

	// Apply exponential backoff based on consecutive throttled responses
	if config.ExponentialRequestDelay > 1.0 {
		count := float64(t.counter.Load())
		baseDelay = time.Duration(float64(baseDelay) * math.Pow(config.ExponentialRequestDelay, count))

		// Cap at maxRequestDelay
		if baseDelay > config.MaxRequestDelay {
			baseDelay = config.MaxRequestDelay
		}
	}

	// Calculate jitter
	jitterPercent := float64(config.RequestDelayJitter) / 100.0
	jitterNanos := int64(float64(baseDelay.Nanoseconds()) * jitterPercent)

	// Only positive jitter
	jitter := time.Duration(rand.Int63n(jitterNanos))

	// Ensure final delay doesn't exceed maxRequestDelay
	finalDelay := baseDelay + jitter
	if finalDelay > config.MaxRequestDelay {
		finalDelay = config.MaxRequestDelay
	}

	return finalDelay
}

// ThrottleRequest throttles the request based on the current throttle rate
func (t *Throttler) ThrottleRequest() {
	if t == nil {
		return
	}

	// Get delay under lock to ensure consistency
	delay := t.GetCurrentThrottleRate()
	if delay > 0 {
		time.Sleep(delay)
	}
}

// UpdateThrottleConfig safely updates throttle configuration
func (t *Throttler) UpdateThrottlerConfig(config *ThrottleConfig) {
	t.config.Store(config)
	t.counter.Store(0) // Reset attempts counter
}

// EnableThrottling enables the throttler
func (t *Throttler) EnableThrottler() {
	if t == nil {
		return
	}
	t.isThrottling.Store(true)
}

// IsThrottlerActive returns true if the throttler is currently active
func (t *Throttler) IsThrottlerActive() bool {
	if t == nil {
		return false
	}
	return t.isThrottling.Load()
}

// DisableThrottler disables the throttler, it does not reset the stats and rates though.
func (t *Throttler) DisableThrottler() {
	if t == nil {
		return
	}
	t.isThrottling.Store(false)
}

// Reset resets the throttler state
func (t *Throttler) ResetThrottler() {
	t.counter.Store(0)
	t.lastDelay.Store(0)
}
