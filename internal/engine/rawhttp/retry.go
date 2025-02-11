package rawhttp

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valyala/fasthttp"
)

type RetryConfig struct {
	mu              sync.RWMutex
	retriedAttempts atomic.Int32
	MaxRetries      int
	InitialInterval time.Duration // Initial delay between retries
	MaxInterval     time.Duration // Maximum delay between retries
	Multiplier      float64       // Multiplier for exponential backoff
}

type Retry struct {
	config          *RetryConfig
	currentInterval time.Duration
}

func NewRetry(config *RetryConfig) *Retry {
	return &Retry{
		config:          config,
		currentInterval: config.InitialInterval,
	}
}

func (r *Retry) Do(fn func() error) error {
	var err error
	for attempt := 0; attempt <= r.config.MaxRetries; attempt++ {
		err = fn()
		if err == nil {
			return nil
		}

		if !IsRetryableError(err) {
			return err
		}

		if attempt == r.config.MaxRetries {
			return err
		}

		// Exponential backoff with jitter
		delay := r.currentInterval
		if delay > r.config.MaxInterval {
			delay = r.config.MaxInterval
		}
		time.Sleep(delay)

		// Increase interval for next attempt
		r.currentInterval = time.Duration(float64(r.currentInterval) * r.config.Multiplier)
	}
	return err
}

// DefaultRetryConfig returns the default retry configuration
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		InitialInterval: 200 * time.Millisecond,
		MaxInterval:     3 * time.Second,
		Multiplier:      1.0,
		MaxRetries:      3,
		mu:              sync.RWMutex{},
	}
}

// IsRetryableError checks if the error should trigger a retry
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}
	return err == io.EOF ||
		errors.Is(err, fasthttp.ErrConnectionClosed)
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
	return rc.retriedAttempts.Load()
}

// Add these methods here instead of in client.go
func (rc *RetryConfig) GetConfig() *RetryConfig {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc
}

func (rc *RetryConfig) SetConfig(cfg *RetryConfig) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// Copy fields individually instead of the entire struct
	rc.InitialInterval = cfg.InitialInterval
	rc.MaxInterval = cfg.MaxInterval
	rc.Multiplier = cfg.Multiplier
	rc.MaxRetries = cfg.MaxRetries

	// For atomic value, use Store instead of direct assignment
	rc.retriedAttempts.Store(cfg.retriedAttempts.Load())
}
