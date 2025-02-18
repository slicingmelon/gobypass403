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

type RetryAction int

const (
	RetryWithConnectionClose RetryAction = iota
	RetryWithoutResponseStreaming
	NoRetry
)

type RetryDecision struct {
	ShouldRetry bool
	Action      RetryAction
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

func IsRetryableError(err error) RetryDecision {
	if err == nil {
		return RetryDecision{false, NoRetry}
	}

	// Check for malformed response error that requires disabling streaming
	if strings.Contains(err.Error(), "cannot find whitespace in the first line") ||
		strings.Contains(err.Error(), "cannot parse response status code") {
		//GB403Logger.Debug().Msgf("Identified as retryable error: %v", err)
		return RetryDecision{true, RetryWithoutResponseStreaming}
	}

	// Standard connection-related errors that require connection close
	if err == io.EOF ||
		errors.Is(err, fasthttp.ErrConnectionClosed) ||
		errors.Is(err, fasthttp.ErrTimeout) ||
		strings.Contains(err.Error(), "timeout") ||
		strings.Contains(err.Error(), "existing connection was forcibly closed") ||
		strings.Contains(err.Error(), "Only one usage of each socket address") {
		return RetryDecision{true, RetryWithConnectionClose}
	}

	return RetryDecision{false, NoRetry}
}
