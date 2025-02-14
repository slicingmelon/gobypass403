package rawhttp

import (
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

type ThrottleConfig struct {
	baseRequestDelay        time.Duration
	maxRequestDelay         time.Duration
	exponentialRequestDelay float64 // Exponential request delay
	requestDelayJitter      int     // For random delay, percentage of variation (0-100)
	throttleOnStatusCodes   []int   // Status codes that trigger throttling
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
		baseRequestDelay:        200 * time.Millisecond,
		maxRequestDelay:         5000 * time.Millisecond,
		requestDelayJitter:      20,  // 20% of the base request delay
		exponentialRequestDelay: 2.0, // Each throttle doubles the delay
		throttleOnStatusCodes:   []int{429, 503, 507},
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
	if matchStatusCodes(statusCode, config.throttleOnStatusCodes) {
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
	baseDelay := config.baseRequestDelay

	// Calculate jitter range (20% of base delay)
	jitterNanos := int64(float64(baseDelay.Nanoseconds()) * 0.2)

	// Ensure jitter range is positive
	if jitterNanos <= 0 {
		return baseDelay
	}

	// Use math/rand instead of crypto/rand for performance
	jitter := time.Duration(rand.Int63n(jitterNanos))
	if rand.Int63n(2) == 1 {
		jitter = -jitter
	}

	adjusted := baseDelay + jitter
	if adjusted < 0 {
		adjusted = 0
	}

	return adjusted
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
