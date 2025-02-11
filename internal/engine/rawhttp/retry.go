package rawhttp

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/valyala/fasthttp"
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
	MaxRetries int

	retriedAttempts atomic.Int32

	// currentInterval tracks the current sleep time.
	currentInterval time.Duration

	mu sync.RWMutex
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
		InitialDelay:    300 * time.Millisecond,
		MaxBackoffTime:  32 * time.Second,
		Multiplier:      2.0,
		MaxRetries:      3,
		currentInterval: 500 * time.Millisecond,
		mu:              sync.RWMutex{},
	}
}

// IsRetryableError checks if the error should trigger a retry
func IsRetryableError(err error) bool {
	return err == io.EOF || errors.Is(err, fasthttp.ErrConnectionClosed)
}

// ShouldRetry checks if we can retry based on attempts and config
func (rc *RetryConfig) ShouldRetry() bool {
	return rc.retriedAttempts.Load() < int32(rc.MaxRetries)
}

// IncrementAttempts increments the retry counter
func (rc *RetryConfig) IncrementAttempts() int32 {
	return rc.retriedAttempts.Add(1)
}

// GetRetriedAttempts returns current retry count
func (rc *RetryConfig) GetRetriedAttempts() int32 {
	GB403Logger.Warning().Msgf("GetRetriedAttempts: %d\n", rc.retriedAttempts.Load())
	return rc.retriedAttempts.Load()
}
