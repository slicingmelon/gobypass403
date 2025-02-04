package error

// Custom Error Handler implementing a cache for errors statistics.
// It is used to track the number of errors for better debugging.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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
	ErrBodyTooLarge          = fasthttp.ErrBodyTooLarge // "body size exceeds the given limit"
	ErrInvalidResponseHeader = errors.New("invalid header")
	ErrConnForciblyClosedWin = errors.New("wsarecv: An existing connection was forcibly closed by the remote host")
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
	cache             *fastcache.Cache
	cacheLock         sync.RWMutex
	whitelist         map[string]struct{}
	whitelistLock     sync.RWMutex
	stripErrorMsgLock sync.RWMutex
}

type ErrorCache struct {
	Count         int64            `json:"count"`
	FirstSeen     time.Time        `json:"first_seen"`
	LastSeen      time.Time        `json:"last_seen"`
	BypassModules map[string]int64 `json:"bypass_modules,omitempty"`
	ErrorSources  map[string]int64 `json:"error_sources"`
}

// NewErrorHandler creates a new ErrorHandler instance
// cacheSizeMB is the size of the cache in MB
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

// AddWhitelistedErrors adds errors to the whitelist
// This is needed as fasthttp returns some errors that are not actual errors..
func (e *ErrorHandler) AddWhitelistedErrors(errors ...string) {
	e.whitelistLock.Lock()
	defer e.whitelistLock.Unlock()

	for _, err := range errors {
		e.whitelist[err] = struct{}{}
	}
}

// Quick check to see if the error is whitelisted
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

// StripErrorMessage strips the error message to a more readable format
// This is needed as some connection errors include a different port number messing up the cache stats
func (e *ErrorHandler) StripErrorMessage(err error) string {
	e.stripErrorMsgLock.Lock()
	defer e.stripErrorMsgLock.Unlock()

	// Check the error message itself
	errMsg := err.Error()
	if strings.Contains(errMsg, ErrConnForciblyClosedWin.Error()) {
		return ErrConnForciblyClosedWin.Error()
	}
	return errMsg
}

// Core function, HandleError handles an error and adds it to the cache
func (e *ErrorHandler) HandleError(err error, ctx ErrorContext) error {
	if err == nil || e.IsWhitelisted(err) {
		return nil
	}

	host := string(ctx.Host)
	errMsg := e.StripErrorMessage(err)

	e.cacheLock.Lock()
	defer e.cacheLock.Unlock()

	// Add to index first
	e.addToIndex(host, errMsg)

	// Update error stats
	key := []byte(fmt.Sprintf("h:%s:e:%s", host, errMsg))
	var errorStats ErrorCache
	if data := e.cache.Get(nil, key); data != nil {
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
		e.cache.Set(key, data)
	}

	return err
}

// PrintErrorStats prints the error stats, used for debugging, called at the end of the scan
func (e *ErrorHandler) PrintErrorStats() {
	e.cacheLock.RLock()
	defer e.cacheLock.RUnlock()

	var buf bytes.Buffer
	var stats fastcache.Stats
	e.cache.UpdateStats(&stats)

	// Print header stats
	fmt.Fprintln(&buf, "=== Error Statistics ===")
	fmt.Fprintln(&buf, "Memory Usage:")
	fmt.Fprintf(&buf, "Cache Size: %d MB (allocated)\n", stats.BytesSize/(1024*1024))
	fmt.Fprintf(&buf, "Max Cache Size: %d MB\n", stats.MaxBytesSize/(1024*1024))
	fmt.Fprintf(&buf, "Cache Entries: %d\n", stats.EntriesCount)
	fmt.Fprintf(&buf, "Cache Get Calls: %d\n", stats.GetCalls)
	fmt.Fprintf(&buf, "Cache Set Calls: %d\n", stats.SetCalls)
	fmt.Fprintf(&buf, "Cache Misses: %d\n", stats.Misses)

	// Get all keys with prefix "h:"
	// Since fastcache doesn't provide iteration, we need to maintain a separate index
	indexKey := []byte("index:hosts")
	if hostsData := e.cache.Get(nil, indexKey); hostsData != nil {
		var hosts []string
		json.Unmarshal(hostsData, &hosts)

		for _, host := range hosts {
			// For each host, get its errors
			hostKey := []byte(fmt.Sprintf("h:%s:e:index", host))
			if errorsData := e.cache.Get(nil, hostKey); errorsData != nil {
				var errors []string
				json.Unmarshal(errorsData, &errors)

				for _, errMsg := range errors {
					key := []byte(fmt.Sprintf("h:%s:e:%s", host, errMsg))
					if data := e.cache.Get(nil, key); data != nil {
						var errorStats ErrorCache
						json.Unmarshal(data, &errorStats)

						fmt.Fprintln(&buf)
						fmt.Fprintf(&buf, "Error: %s\n", errMsg)
						fmt.Fprintf(&buf, "Count: %d occurrences\n", errorStats.Count)
						fmt.Fprintf(&buf, "First Seen: %s\n", errorStats.FirstSeen.Format(time.RFC3339))
						fmt.Fprintf(&buf, "Last Seen: %s\n", errorStats.LastSeen.Format(time.RFC3339))

						fmt.Fprintln(&buf, "Error Sources:")
						for source, count := range errorStats.ErrorSources {
							fmt.Fprintf(&buf, "  - %s: %d times\n", source, count)
						}

						if len(errorStats.BypassModules) > 0 {
							fmt.Fprintf(&buf, "  Host: %s\n", host)
							for module, count := range errorStats.BypassModules {
								if module != "" {
									fmt.Fprintf(&buf, "    - Module %s: %d times\n", module, count)
								}
							}
						}
					}
				}
			}
		}
	}

	fmt.Println(buf.String())
}

// Reset the error cache
func (e *ErrorHandler) Reset() {
	e.cacheLock.Lock()
	defer e.cacheLock.Unlock()
	e.cache.Reset()
}

// Helper method to maintain the host index
func (e *ErrorHandler) addToIndex(host, errMsg string) {
	// Update hosts index
	indexKey := []byte("index:hosts")
	var hosts []string
	if hostsData := e.cache.Get(nil, indexKey); hostsData != nil {
		json.Unmarshal(hostsData, &hosts)
	}
	if !slices.Contains(hosts, host) {
		hosts = append(hosts, host)
		if data, err := json.Marshal(hosts); err == nil {
			e.cache.Set(indexKey, data)
		}
	}

	// Update host's errors index
	hostKey := []byte(fmt.Sprintf("h:%s:e:index", host))
	var errors []string
	if errorsData := e.cache.Get(nil, hostKey); errorsData != nil {
		json.Unmarshal(errorsData, &errors)
	}
	if !slices.Contains(errors, errMsg) {
		errors = append(errors, errMsg)
		if data, err := json.Marshal(errors); err == nil {
			e.cache.Set(hostKey, data)
		}
	}
}
