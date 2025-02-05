package rawhttp

import (
	"sync/atomic"
	"time"
)

type RetryConfig struct {
	// InitialInterval is the initial time interval for backoff algorithm.
	InitialDelay time.Duration

	// MaxBackoffTime is the maximum time duration for backoff algorithm. It limits
	// the maximum sleep time.
	MaxBackoffTime time.Duration

	// Multiplier is a multiplier number of the backoff algorithm.
	Multiplier float64

	// MaxRetryCount is the maximum number of retry count.
	MaxRetryCount int

	// currentInterval tracks the current sleep time.
	currentInterval time.Duration
}

type RetryManager struct {
	RetryConfig *RetryConfig
	ShouldRetry atomic.Bool
}

// GetRetryConfig returns the current retry configuration
func (c *HTTPClient) GetRetryConfig() *RetryConfig {
	c.mu.RLock()

	defer c.mu.RUnlock()
	return c.retryConfig
}

// SetRetryConfig updates the retry configuration
func (c *HTTPClient) SetRetryConfig(cfg *RetryConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.retryConfig = cfg
}

// DefaultRetryConfig returns the default retry configuration
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		InitialDelay:    1 * time.Second,
		MaxBackoffTime:  32 * time.Second,
		Multiplier:      2.0,
		MaxRetryCount:   3,
		currentInterval: 1 * time.Second,
	}
}
