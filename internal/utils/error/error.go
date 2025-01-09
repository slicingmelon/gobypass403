package error

// Custom Error Handler

import (
	"bytes"
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
	ErrBodyTooLarge          = fasthttp.ErrBodyTooLarge
	ErrInvalidResponseHeader = errors.New("invalid header")
)

// ErrorContext holds metadata about where/when the error occurred
type ErrorContext struct {
	Host         []byte    `json:"host"`
	BypassModule []byte    `json:"bypass_module"`
	TargetURL    []byte    `json:"url"`
	ErrorSource  []byte    `json:"error_source"`
	DebugToken   []byte    `json:"debug_token"`
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

type ErrorHandler struct {
	cache         *fastcache.Cache
	cacheLock     sync.RWMutex
	whitelist     map[string]struct{}
	whitelistLock sync.RWMutex
}

type ErrorCache struct {
	Count         int64            `json:"count"`
	FirstSeen     time.Time        `json:"first_seen"`
	LastSeen      time.Time        `json:"last_seen"`
	BypassModules map[string]int64 `json:"bypass_modules,omitempty"`
	ErrorSources  map[string]int64 `json:"error_sources"`
}

func NewErrorHandler(cacheSizeMB int) *ErrorHandler {
	handler := &ErrorHandler{
		cache:     fastcache.New(cacheSizeMB * 1024 * 1024),
		whitelist: make(map[string]struct{}),
	}

	// Initialize default whitelisted errors
	handler.AddWhitelistedErrors(
		ErrBodyTooLarge.Error(),
		ErrInvalidResponseHeader.Error(),
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

	host := string(ctx.Host)
	errMsg := err.Error()

	// Update host error stats
	hostKey := fmt.Sprintf("h:%s:e:%s", host, errMsg)

	e.cacheLock.Lock()
	defer e.cacheLock.Unlock()

	var errorStats ErrorCache
	if data := e.cache.Get(nil, []byte(hostKey)); data != nil {
		json.Unmarshal(data, &errorStats)
	} else {
		errorStats = ErrorCache{
			FirstSeen:     time.Now(),
			BypassModules: make(map[string]int64),
			ErrorSources:  make(map[string]int64),
		}
	}

	// Update stats
	errorStats.Count++
	errorStats.LastSeen = time.Now()
	errorStats.ErrorSources[string(ctx.ErrorSource)]++

	if len(ctx.BypassModule) > 0 {
		errorStats.BypassModules[string(ctx.BypassModule)]++
	}

	// Store updated stats
	if data, err := json.Marshal(errorStats); err == nil {
		e.cache.Set([]byte(hostKey), data)
	}

	return err
}

func (e *ErrorHandler) PrintErrorStats() {
	e.statsLock.RLock()
	defer e.statsLock.RUnlock()

	var buf bytes.Buffer
	var stats fastcache.Stats
	var totalContextSize int64
	var totalErrorKeys int
	var totalErrorSources int

	// Get cache stats
	e.cache.UpdateStats(&stats)

	for errKey, stat := range e.stats {
		totalErrorKeys += len(errKey)
		totalErrorSources += len(stat.ErrorSources)
		if data := e.cache.Get(nil, []byte(fmt.Sprintf("%s:%d", errKey, stat.Count))); data != nil {
			totalContextSize += int64(len(data))
		}
	}

	// Build the complete output in memory first
	fmt.Fprintln(&buf, "=== Error Statistics ===")
	fmt.Fprintln(&buf, "Memory Usage:")
	fmt.Fprintf(&buf, "Cache Size: %d MB (allocated)\n", stats.BytesSize/(1024*1024))
	fmt.Fprintf(&buf, "Max Cache Size: %d MB\n", stats.MaxBytesSize/(1024*1024))
	fmt.Fprintf(&buf, "Active Cache Usage: %.2f MB\n", float64(totalContextSize)/(1024*1024))
	fmt.Fprintf(&buf, "Unique Errors: %d\n", len(e.stats))
	fmt.Fprintf(&buf, "Total Error Sources: %d\n", totalErrorSources)
	fmt.Fprintf(&buf, "Cache Entries: %d\n", stats.EntriesCount)
	fmt.Fprintf(&buf, "Cache Get Calls: %d\n", stats.GetCalls)
	fmt.Fprintf(&buf, "Cache Set Calls: %d\n", stats.SetCalls)
	fmt.Fprintf(&buf, "Cache Misses: %d\n", stats.Misses)

	// Print error details
	for errKey, stat := range e.stats {
		fmt.Fprintln(&buf)
		fmt.Fprintf(&buf, "Error: %s\n", errKey)
		fmt.Fprintf(&buf, "Count: %d occurrences\n", stat.Count)
		fmt.Fprintf(&buf, "First Seen: %s\n", stat.FirstSeen.Format(time.RFC3339))
		fmt.Fprintf(&buf, "Last Seen: %s\n", stat.LastSeen.Format(time.RFC3339))

		fmt.Fprintln(&buf, "Error Sources:")
		for source, count := range stat.ErrorSources {
			fmt.Fprintf(&buf, "  - %s: %d times\n", source, count)
		}

		// Group by host and bypass module
		hostStats := make(map[string]map[string]int) // host -> bypassModule -> count
		for i := int64(1); i <= stat.Count; i++ {
			if contextJSON := e.cache.Get(nil, []byte(fmt.Sprintf("%s:%d", errKey, i))); contextJSON != nil {
				var ctx ErrorContext
				if err := json.Unmarshal(contextJSON, &ctx); err == nil {
					host := string(ctx.Host)
					bypassModule := string(ctx.BypassModule)
					if _, exists := hostStats[host]; !exists {
						hostStats[host] = make(map[string]int)
					}
					hostStats[host][bypassModule]++
				}
			}
		}

		fmt.Fprintln(&buf, "Affected Hosts:")
		for host, modules := range hostStats {
			fmt.Fprintf(&buf, "  Host: %s\n", host)
			for module, count := range modules {
				if module != "" {
					fmt.Fprintf(&buf, "    - Module %s: %d times\n", module, count)
				}
			}
		}
	}

	fmt.Println(buf.String())
}

func (e *ErrorHandler) Reset() {
	e.statsLock.Lock()
	e.stats = make(map[string]*ErrorStats)
	e.statsLock.Unlock()
	e.cache.Reset()
}
