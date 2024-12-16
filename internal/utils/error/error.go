package error

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/VictoriaMetrics/fastcache"
)

// ErrorContext holds metadata about where/when the error occurred
type ErrorContext struct {
	Host        string    `json:"host"`
	BypassMode  string    `json:"bypass_mode"`
	URL         string    `json:"url"`
	ErrorSource string    `json:"error_source"`
	Timestamp   time.Time `json:"timestamp"`
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

	// Initialize default whitelisted errors
	handler.AddWhitelistedErrors(
		"fasthttp.ErrBodyTooLarge",
		"fasthttp.ErrConnectionClosed",
		"fasthttp.ErrNoFreeConns",
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

	_, ok := e.whitelist[err.Error()]
	return ok
}

func (e *ErrorHandler) HandleError(err error, ctx ErrorContext) {
	if err == nil || e.IsWhitelisted(err) {
		return
	}

	errKey := err.Error()
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
	stat.ErrorSources[ctx.ErrorSource]++
	e.statsLock.Unlock()

	// Cache error context
	contextJSON, _ := json.Marshal(ctx)
	e.cache.Set([]byte(fmt.Sprintf("%s:%d", errKey, stat.Count)), contextJSON)
}

func (e *ErrorHandler) PrintErrorStats() {
	e.statsLock.RLock()
	defer e.statsLock.RUnlock()

	fmt.Println("\n=== Error Statistics ===")
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
