package error

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/VictoriaMetrics/fastcache"
	"github.com/valyala/fasthttp"
)

const (
	DefaultCacheSizeMB = 32 // MB
)

var (
	ErrBodyTooLarge     = fasthttp.ErrBodyTooLarge
	ErrConnectionClosed = fasthttp.ErrConnectionClosed
	ErrNoFreeConns      = fasthttp.ErrNoFreeConns
)

// ErrorContext holds metadata about where/when the error occurred
type ErrorContext struct {
	Host         []byte    `json:"host"`
	BypassModule []byte    `json:"bypass_module"`
	TargetURL    []byte    `json:"url"`
	ErrorSource  []byte    `json:"error_source"`
	Timestamp    time.Time `json:"timestamp"`
}

// ErrorStats tracks statistics for each error type
type ErrorStats struct {
	Count        int64            `json:"count"`
	FirstSeen    time.Time        `json:"first_seen"`
	LastSeen     time.Time        `json:"last_seen"`
	ErrorSources map[string]int64 `json:"error_sources"`
	Contexts     []ErrorContext   `json:"contexts,omitempty"`
}

// ErrorHandler manages error tracking and caching
type ErrorHandler struct {
	cache         *fastcache.Cache
	statsLock     sync.RWMutex
	stats         map[string]*ErrorStats
	whitelistLock sync.RWMutex
	whitelist     map[string]struct{}
}

func NewErrorHandler(cacheSizeMB int) *ErrorHandler {
	handler := &ErrorHandler{
		cache:     fastcache.New(cacheSizeMB * 1024 * 1024),
		stats:     make(map[string]*ErrorStats),
		whitelist: make(map[string]struct{}),
	}

	// Initialize default whitelisted errors with actual error messages
	handler.AddWhitelistedErrors(
		ErrBodyTooLarge.Error(),
	)

	return handler
}

func (e *ErrorHandler) AddWhitelistedErrors(errors ...string) {
	e.whitelistLock.Lock()
	defer e.whitelistLock.Unlock()

	for _, err := range errors {
		e.whitelist[err] = struct{}{}
	}
}

func (e *ErrorHandler) IsWhitelisted(err error) bool {
	e.whitelistLock.RLock()
	defer e.whitelistLock.RUnlock()

	// Check the error message itself
	errMsg := err.Error()
	for whitelisted := range e.whitelist {
		if strings.Contains(errMsg, whitelisted) {
			return true
		}
	}
	return false
}

func (e *ErrorHandler) HandleError(err error, ctx ErrorContext) error {
	if err == nil || e.IsWhitelisted(err) {
		return nil
	}

	// Get the root error
	rootErr := errors.Unwrap(err)
	if rootErr == nil {
		rootErr = err
	}
	errKey := rootErr.Error()

	ctx.Timestamp = time.Now()

	// Update stats
	e.statsLock.Lock()
	if _, exists := e.stats[errKey]; !exists {
		e.stats[errKey] = &ErrorStats{
			FirstSeen:    ctx.Timestamp,
			ErrorSources: make(map[string]int64),
		}
	}

	stat := e.stats[errKey]
	stat.Count++
	stat.LastSeen = ctx.Timestamp
	stat.ErrorSources[string(ctx.ErrorSource)]++
	e.statsLock.Unlock()

	// Cache error context
	contextJSON, marshalErr := json.Marshal(ctx)
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal error context: %w", err)
	}

	e.cache.Set([]byte(fmt.Sprintf("%s:%d", errKey, stat.Count)), contextJSON)
	return err
}

func (e *ErrorHandler) PrintErrorStats() {
	e.statsLock.RLock()
	defer e.statsLock.RUnlock()

	fmt.Println("\n=== Error Statistics ===")

	// Calculate memory usage
	var totalContextSize int64
	var totalErrorKeys int
	var totalErrorSources int
	var stats fastcache.Stats

	// Get cache stats
	e.cache.UpdateStats(&stats)

	for errKey, stat := range e.stats {
		totalErrorKeys += len(errKey)
		totalErrorSources += len(stat.ErrorSources)

		// Calculate JSON size for each stored context
		if data := e.cache.Get(nil, []byte(fmt.Sprintf("%s:%d", errKey, stat.Count))); data != nil {
			totalContextSize += int64(len(data))
		}
	}

	// Print memory stats
	fmt.Printf("\nMemory Usage:\n")
	fmt.Printf("Cache Size: %d MB (allocated)\n", stats.BytesSize/(1024*1024))
	fmt.Printf("Max Cache Size: %d MB\n", stats.MaxBytesSize/(1024*1024))
	fmt.Printf("Active Cache Usage: %.2f MB\n", float64(totalContextSize)/(1024*1024))
	fmt.Printf("Unique Errors: %d\n", len(e.stats))
	fmt.Printf("Total Error Sources: %d\n", totalErrorSources)
	fmt.Printf("Cache Entries: %d\n", stats.EntriesCount)
	fmt.Printf("Cache Get Calls: %d\n", stats.GetCalls)
	fmt.Printf("Cache Set Calls: %d\n", stats.SetCalls)
	fmt.Printf("Cache Misses: %d\n", stats.Misses)

	// Print error details
	for errKey, stat := range e.stats {
		fmt.Printf("\nError: %s\n", errKey)
		fmt.Printf("Count: %d occurrences\n", stat.Count)
		fmt.Printf("First Seen: %s\n", stat.FirstSeen.Format(time.RFC3339))
		fmt.Printf("Last Seen: %s\n", stat.LastSeen.Format(time.RFC3339))

		fmt.Println("Error Sources:")
		for source, count := range stat.ErrorSources {
			fmt.Printf("  - %s: %d times\n", source, count)
		}
	}
}

func (e *ErrorHandler) Reset() {
	e.statsLock.Lock()
	e.stats = make(map[string]*ErrorStats)
	e.statsLock.Unlock()
	e.cache.Reset()
}
