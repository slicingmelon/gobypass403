package rawhttp

import (
	"crypto/rand"
	"math"
	"math/big"
	"sync/atomic"
	"time"

	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
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
	config := t.config.Load()
	if matchStatusCodes(statusCode, config.ThrottleOnStatusCodes) {
		wasThrottling := t.isThrottling.Swap(true)
		t.counter.Add(1)
		if !wasThrottling {
			GB403Logger.Warning().Msgf("Auto throttling enabled due to status code: %d", statusCode)
		}
		return true
	}
	return false
}

// GetCurrentThrottleRate calculates the next delay based on config and attempts
func (t *Throttler) GetCurrentThrottleRate() time.Duration {
	config := t.config.Load()
	delay := config.BaseRequestDelay

	// Apply exponential delay if configured
	if config.ExponentialRequestDelay > 0 {
		attempts := t.counter.Load()
		multiplier := math.Pow(config.ExponentialRequestDelay, float64(attempts))
		delay = time.Duration(float64(config.BaseRequestDelay) * multiplier)
	}

	// Apply jitter if configured
	if config.RequestDelayJitter > 0 {
		jitterRange := int64(float64(delay.Nanoseconds()) * float64(config.RequestDelayJitter) / 100.0)
		if jitter, err := rand.Int(rand.Reader, big.NewInt(jitterRange)); err == nil {
			delay += time.Duration(jitter.Int64())
		}
	}

	// Ensure we don't exceed max delay
	if delay > config.MaxRequestDelay {
		delay = config.MaxRequestDelay
	}

	t.lastDelay.Store(int64(delay))
	return delay
}

// ThrottleRequest throttles the request based on the current throttle rate
func (t *Throttler) ThrottleRequest() {
	// Apply throttler delay if active
	if t != nil {
		if delay := t.GetCurrentThrottleRate(); delay > 0 {
			time.Sleep(delay)
		}
	}
}

// UpdateThrottleConfig safely updates throttle configuration
func (t *Throttler) UpdateThrottleConfig(config *ThrottleConfig) {
	t.config.Store(config)
	t.counter.Store(0) // Reset attempts counter
}

// Reset resets the throttler state
func (t *Throttler) Reset() {
	wasThrottling := t.isThrottling.Swap(false)
	t.counter.Store(0)
	t.lastDelay.Store(0)
	if wasThrottling {
		GB403Logger.Info().Msgf("Auto throttling disabled - returning to normal request rate")
	}
}
