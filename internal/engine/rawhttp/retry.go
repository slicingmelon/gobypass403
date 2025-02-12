package rawhttp

import (
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valyala/fasthttp"
)

type RetryConfig struct {
	PerReqRetriedAttempts atomic.Int32
	MaxRetries            int
	RetryDelay            time.Duration
	mu                    sync.RWMutex
}

func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries: 2,
		RetryDelay: 500 * time.Millisecond,
	}
}

// GetRetryConfig returns the current retry configuration
func (rc *RetryConfig) GetRetryConfig() *RetryConfig {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc
}

// SetRetryConfig updates the retry configuration
func (rc *RetryConfig) SetRetryConfig(config *RetryConfig) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.MaxRetries = config.MaxRetries
	rc.RetryDelay = config.RetryDelay
}

func (rc *RetryConfig) GetPerReqRetriedAttempts() int32 {
	return rc.PerReqRetriedAttempts.Load()
}

func (rc *RetryConfig) ResetPerReqAttempts() {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.PerReqRetriedAttempts.Store(0)
}

func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Check for specific error types
	if err == io.EOF || errors.Is(err, fasthttp.ErrConnectionClosed) || errors.Is(err, fasthttp.ErrTimeout) ||
		strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "existing connection was forcibly closed") {
		return true
	}

	return false
}
