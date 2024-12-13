package error

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// ErrorStats holds detailed error statistics
type ErrorStats struct {
	// General stats
	TotalErrors    uint64    `json:"total_errors"`
	FirstErrorTime time.Time `json:"first_error"`
	LastErrorTime  time.Time `json:"last_error"`

	// Error type counters
	TimeoutErrors    uint64 `json:"timeout_errors"`
	ConnectionErrors uint64 `json:"connection_errors"`
	TLSErrors        uint64 `json:"tls_errors"`
	PayloadErrors    uint64 `json:"payload_errors"`

	// Host stats
	UniqueHosts  uint64 `json:"unique_hosts"`
	BlockedHosts uint64 `json:"blocked_hosts"`

	// Cache performance
	CacheHits   uint64 `json:"cache_hits"`
	CacheMisses uint64 `json:"cache_misses"`
	CacheResets uint64 `json:"cache_resets"`
}

// Per-host statistics
type HostStats struct {
	FirstError     time.Time         `json:"first_error"`
	LastError      time.Time         `json:"last_error"`
	ErrorCount     uint32            `json:"error_count"`
	ErrorTypes     map[string]uint32 `json:"error_types"`
	LastStatusCode int               `json:"last_status_code"`
}

func (h *ErrorHandler) RecordError(host string, err error, statusCode int) {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()

	// Update global stats
	atomic.AddUint64(&h.stats.TotalErrors, 1)
	if h.stats.FirstErrorTime.IsZero() {
		h.stats.FirstErrorTime = now
	}
	h.stats.LastErrorTime = now

	// Update host-specific stats
	if h.hostStats[host] == nil {
		h.hostStats[host] = &HostStats{
			FirstError: now,
			ErrorTypes: make(map[string]uint32),
		}
		atomic.AddUint64(&h.stats.UniqueHosts, 1)
	}

	hostStat := h.hostStats[host]
	hostStat.LastError = now
	hostStat.ErrorCount++
	hostStat.LastStatusCode = statusCode

	// Categorize error with all possible error types
	switch err {
	case ErrTooManyTimeouts:
		atomic.AddUint64(&h.stats.TimeoutErrors, 1)
		hostStat.ErrorTypes["timeout"]++
	case ErrTooManyConnections:
		atomic.AddUint64(&h.stats.ConnectionErrors, 1)
		hostStat.ErrorTypes["connection"]++
	case ErrTLSHandshake, ErrInvalidCertificate:
		atomic.AddUint64(&h.stats.TLSErrors, 1)
		hostStat.ErrorTypes["tls"]++
	case ErrInvalidPayload, ErrPayloadTooLarge, ErrEmptyPayload:
		atomic.AddUint64(&h.stats.PayloadErrors, 1)
		hostStat.ErrorTypes["payload"]++
	}

	// Update blocked hosts count if permanent error
	if IsPermanentError(err) {
		atomic.AddUint64(&h.stats.BlockedHosts, 1)
	}
}

// GetHostStats returns statistics for a specific host
func (h *ErrorHandler) GetHostStats(host string) *HostStats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.hostStats[host]
}

// ExportStats exports all statistics to JSON
func (h *ErrorHandler) ExportStats() ([]byte, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	export := struct {
		GlobalStats ErrorStats            `json:"global_stats"`
		HostStats   map[string]*HostStats `json:"host_stats"` // Changed to pointer type
		Timestamp   time.Time             `json:"timestamp"`
	}{
		GlobalStats: h.stats,
		HostStats:   h.hostStats,
		Timestamp:   time.Now(),
	}

	return json.MarshalIndent(export, "", "  ")
}

// GenerateReport creates a detailed error report
func (h *ErrorHandler) GenerateReport() string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	report := strings.Builder{}
	report.WriteString("Error Handler Report\n")
	report.WriteString("===================\n\n")

	// Global statistics
	fmt.Fprintf(&report, "Total Errors: %d\n", h.stats.TotalErrors)
	fmt.Fprintf(&report, "Unique Hosts: %d\n", h.stats.UniqueHosts)
	fmt.Fprintf(&report, "Blocked Hosts: %d\n", h.stats.BlockedHosts)
	fmt.Fprintf(&report, "First Error: %s\n", h.stats.FirstErrorTime)
	fmt.Fprintf(&report, "Last Error: %s\n\n", h.stats.LastErrorTime)

	// Error type breakdown
	fmt.Fprintf(&report, "Error Type Breakdown:\n")
	fmt.Fprintf(&report, "- Timeouts: %d\n", h.stats.TimeoutErrors)
	fmt.Fprintf(&report, "- TLS Errors: %d\n", h.stats.TLSErrors)
	fmt.Fprintf(&report, "- Connection Errors: %d\n", h.stats.ConnectionErrors)

	return report.String()
}

// Cleanup releases resources
func (h *ErrorHandler) Cleanup() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.cache.Reset()
	h.hostStats = make(map[string]*HostStats)
	h.stats = ErrorStats{}
}
