// File: internal/utils/error/error.go
package error

import (
	"github.com/VictoriaMetrics/fastcache"
)

// ErrorContext holds metadata about the error occurrence
type ErrorContext struct {
	Host       []byte
	BypassMode []byte
	WorkerID   []byte
	URL        []byte
	Timestamp  []byte
}

// ErrorHandler wraps fastcache for error tracking
type ErrorHandler struct {
	cache *fastcache.Cache
}

func NewErrorHandler() *ErrorHandler {
	// Minimum 32MB as per fastcache docs
	return &ErrorHandler{
		cache: fastcache.New(32 * 1024 * 1024),
	}
}

// HandleError stores error context in cache
func (h *ErrorHandler) HandleError(ctx *ErrorContext) {
	if ctx == nil {
		return
	}

	// Create composite key: host + bypass mode
	key := append([]byte{}, ctx.Host...)
	key = append(key, '_')
	key = append(key, ctx.BypassMode...)

	// Store error context
	value := append([]byte{}, ctx.WorkerID...)
	value = append(value, '_')
	value = append(value, ctx.URL...)
	value = append(value, '_')
	value = append(value, ctx.Timestamp...)

	h.cache.Set(key, value)
}

// GetStats returns cache statistics
func (h *ErrorHandler) GetStats() *fastcache.Stats {
	stats := &fastcache.Stats{}
	h.cache.UpdateStats(stats)
	return stats
}

// Close releases cache resources
func (h *ErrorHandler) Close() {
	if h.cache != nil {
		h.cache.Reset()
	}
}
