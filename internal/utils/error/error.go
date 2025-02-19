package error

// // Custom Error Handler implementing a cache for errors statistics.
// // It is used to track the number of errors for better debugging.

// import (
// 	"encoding/json"
// 	"errors"
// 	"fmt"
// 	"slices"
// 	"strings"
// 	"sync"
// 	"sync/atomic"
// 	"time"

// 	"github.com/VictoriaMetrics/fastcache"
// 	"github.com/valyala/fasthttp"
// )

// const (
// 	DefaultCacheSizeMB = 32 // MB
// )

// var (
// 	instance *ErrorHandler
// 	once     sync.Once
// )

// var (
// 	ErrBodyTooLarge          = fasthttp.ErrBodyTooLarge // "body size exceeds the given limit"
// 	ErrInvalidResponseHeader = errors.New("invalid header")
// 	ErrConnForciblyClosedWin = errors.New("wsarecv: An existing connection was forcibly closed by the remote host")
// )

// var defaultWhitelistedErrors = []error{
// 	ErrBodyTooLarge,
// 	ErrInvalidResponseHeader,
// 	//ErrConnForciblyClosedWin,
// }

// var defaultWhitelistedErrorsStr = []string{
// 	ErrBodyTooLarge.Error(),
// 	ErrInvalidResponseHeader.Error(),
// 	ErrConnForciblyClosedWin.Error(),
// }

// // ErrorContext holds metadata about where/when the error occurred
// type ErrorContext struct {
// 	TargetURL    []byte
// 	ErrorSource  []byte
// 	Host         []byte
// 	BypassModule []byte
// 	DebugToken   []byte
// }

// // ErrorStats tracks statistics for each error type
// type ErrorStats struct {
// 	Count         atomic.Int64
// 	FirstSeen     time.Time                 // Exported
// 	LastSeen      atomic.Pointer[time.Time] // Exported
// 	ErrorSources  sync.Map                  // Exported
// 	BypassModules sync.Map                  // Exported
// 	DebugTokens   []string                  // Exported
// 	tokensMutex   sync.RWMutex              // Can stay unexported
// }

// type ErrorHandler struct {
// 	cache          *fastcache.Cache
// 	whitelist      sync.Map
// 	statsPool      sync.Pool
// 	whitelistStats sync.Map
// 	cacheLock      sync.RWMutex
// }

// type ErrorCache struct {
// 	count         atomic.Int64
// 	firstSeen     time.Time
// 	lastSeen      atomic.Pointer[time.Time]
// 	bypassModules sync.Map
// 	errorSources  sync.Map
// 	debugTokens   []string
// 	tokensMutex   sync.RWMutex
// }

// // NewErrorHandler creates a new ErrorHandler instance
// // cacheSizeMB is the size of the cache in MB
// func NewErrorHandler(cacheSizeMB int) *ErrorHandler {
// 	handler := &ErrorHandler{
// 		cache: fastcache.New(cacheSizeMB * 1024 * 1024),
// 		statsPool: sync.Pool{
// 			New: func() interface{} {
// 				now := time.Now()
// 				stats := &ErrorStats{
// 					FirstSeen:   now,
// 					DebugTokens: make([]string, 0),
// 				}
// 				// Initialize atomic pointer
// 				nowCopy := now
// 				stats.LastSeen.Store(&nowCopy)
// 				return stats
// 			},
// 		},
// 	}

// 	handler.AddWhitelistedErrors(defaultWhitelistedErrorsStr...)

// 	return handler
// }

// // GetErrorHandler returns the singleton instance of the ErrorHandler
// func GetErrorHandler(cacheSizeMB ...int) *ErrorHandler {
// 	once.Do(func() {
// 		size := DefaultCacheSizeMB
// 		if len(cacheSizeMB) > 0 {
// 			size = cacheSizeMB[0]
// 		}
// 		instance = NewErrorHandler(size)
// 	})
// 	return instance
// }

// func ResetInstance() {
// 	instance = nil
// 	once = sync.Once{}
// }

// // AddWhitelistedErrors adds errors to the whitelist
// // This is needed as fasthttp returns some errors that are not actual errors..
// func (e *ErrorHandler) AddWhitelistedErrors(errors ...string) {
// 	for _, err := range errors {
// 		e.whitelist.Store(err, struct{}{})
// 	}
// }

// // Quick check to see if the error is whitelisted
// func (e *ErrorHandler) IsWhitelisted(err error) bool {
// 	if err == nil {
// 		return true
// 	}
// 	errMsg := e.StripErrorMessage(err)
// 	_, exists := e.whitelist.Load(errMsg)
// 	return exists
// }

// // IsWhitelistedError checks if an error is in the default whitelist
// // global function, might be needed in other places
// func IsWhitelistedError(err error) bool {
// 	if err == nil {
// 		return false
// 	}

// 	errMsg := err.Error()
// 	for _, whitelisted := range defaultWhitelistedErrors {
// 		if strings.Contains(errMsg, whitelisted.Error()) {
// 			return true
// 		}
// 	}
// 	return false
// }

// // StripErrorMessage strips the error message to a more readable format
// // This is needed as some connection errors include a different port number messing up the cache stats
// func (e *ErrorHandler) StripErrorMessage(err error) string {
// 	// Check the error message itself
// 	errMsg := err.Error()
// 	if strings.Contains(errMsg, ErrConnForciblyClosedWin.Error()) {
// 		return ErrConnForciblyClosedWin.Error()
// 	}
// 	return errMsg
// }

// // errorCacheJSON is the serializable version
// type errorCacheJSON struct {
// 	Count         int64            `json:"count"`
// 	FirstSeen     time.Time        `json:"first_seen"`
// 	LastSeen      time.Time        `json:"last_seen"`
// 	BypassModules map[string]int64 `json:"bypass_modules"`
// 	ErrorSources  map[string]int64 `json:"error_sources"`
// 	DebugTokens   []string         `json:"debug_tokens"`
// }

// // MarshalJSON implements json.Marshaler
// func (s *ErrorStats) MarshalJSON() ([]byte, error) {
// 	// Create a serializable version of stats
// 	type SerializableStats struct {
// 		Count         int64            `json:"count"`
// 		FirstSeen     time.Time        `json:"first_seen"`
// 		LastSeen      time.Time        `json:"last_seen"`
// 		ErrorSources  map[string]int64 `json:"error_sources"`
// 		BypassModules map[string]int64 `json:"bypass_modules"`
// 		DebugTokens   []string         `json:"debug_tokens"`
// 	}

// 	// Convert sync.Maps to regular maps
// 	errorSources := make(map[string]int64)
// 	s.ErrorSources.Range(func(key, value interface{}) bool {
// 		errorSources[key.(string)] = value.(int64)
// 		return true
// 	})

// 	bypassModules := make(map[string]int64)
// 	s.BypassModules.Range(func(key, value interface{}) bool {
// 		bypassModules[key.(string)] = value.(int64)
// 		return true
// 	})

// 	// Create serializable struct
// 	serializable := SerializableStats{
// 		Count:         s.Count.Load(),
// 		FirstSeen:     s.FirstSeen,
// 		LastSeen:      *s.LastSeen.Load(),
// 		ErrorSources:  errorSources,
// 		BypassModules: bypassModules,
// 		DebugTokens:   s.DebugTokens,
// 	}

// 	return json.Marshal(serializable)
// }

// // UnmarshalJSON implements json.Unmarshaler
// func (s *ErrorStats) UnmarshalJSON(data []byte) error {
// 	var temp struct {
// 		Count         int64            `json:"count"`
// 		FirstSeen     time.Time        `json:"first_seen"`
// 		LastSeen      time.Time        `json:"last_seen"`
// 		ErrorSources  map[string]int64 `json:"error_sources"`
// 		BypassModules map[string]int64 `json:"bypass_modules"`
// 		DebugTokens   []string         `json:"debug_tokens"`
// 	}

// 	if err := json.Unmarshal(data, &temp); err != nil {
// 		return err
// 	}

// 	s.Count.Store(temp.Count)
// 	s.FirstSeen = temp.FirstSeen
// 	lastSeen := temp.LastSeen
// 	s.LastSeen.Store(&lastSeen)

// 	s.ErrorSources = sync.Map{}
// 	for k, v := range temp.ErrorSources {
// 		s.ErrorSources.Store(k, v)
// 	}

// 	s.BypassModules = sync.Map{}
// 	for k, v := range temp.BypassModules {
// 		s.BypassModules.Store(k, v)
// 	}

// 	s.DebugTokens = temp.DebugTokens

// 	return nil
// }

// func (e *ErrorHandler) HandleError(err error, ctx ErrorContext) error {
// 	if err == nil || e.IsWhitelisted(err) {
// 		return nil
// 	}

// 	host := string(ctx.Host)
// 	errMsg := e.StripErrorMessage(err)
// 	key := []byte(fmt.Sprintf("h:%s:e:%s", host, errMsg))

// 	e.cacheLock.Lock()
// 	defer e.cacheLock.Unlock()

// 	var errorStats *ErrorStats
// 	if data := e.cache.Get(nil, key); data != nil {
// 		errorStats = e.statsPool.Get().(*ErrorStats)
// 		if err := json.Unmarshal(data, errorStats); err != nil {
// 			e.statsPool.Put(errorStats)
// 			return err
// 		}
// 	} else {
// 		errorStats = e.statsPool.Get().(*ErrorStats)
// 		now := time.Now()
// 		errorStats.FirstSeen = now
// 		nowCopy := now
// 		errorStats.LastSeen.Store(&nowCopy)
// 		errorStats.Count.Store(1)

// 		errorStats.ErrorSources = sync.Map{}
// 		errorStats.BypassModules = sync.Map{}
// 		errorStats.DebugTokens = make([]string, 0)
// 	}

// 	errorStats.Count.Add(1)

// 	if src := string(ctx.ErrorSource); src != "" {
// 		if val, ok := errorStats.ErrorSources.Load(src); ok {
// 			count := val.(int64)
// 			errorStats.ErrorSources.Store(src, count+1)
// 		} else {
// 			errorStats.ErrorSources.Store(src, int64(1))
// 		}
// 	}

// 	if mod := string(ctx.BypassModule); mod != "" {
// 		if val, ok := errorStats.BypassModules.Load(mod); ok {
// 			count := val.(int64)
// 			errorStats.BypassModules.Store(mod, count+1)
// 		} else {
// 			errorStats.BypassModules.Store(mod, int64(1))
// 		}
// 	}

// 	nowUpdate := time.Now()
// 	errorStats.LastSeen.Store(&nowUpdate)

// 	// Add debug token if present
// 	if len(ctx.DebugToken) > 0 {
// 		errorStats.tokensMutex.Lock()
// 		errorStats.DebugTokens = append(errorStats.DebugTokens, string(ctx.DebugToken))
// 		errorStats.tokensMutex.Unlock()
// 	}

// 	// Store updated stats
// 	if data, err := json.Marshal(errorStats); err == nil {
// 		e.cache.Set(key, data)
// 		e.addToIndex(host, errMsg)
// 	}

// 	e.statsPool.Put(errorStats)

// 	return err
// }

// // PrintErrorStats prints the error stats, used for debugging, called at the end of the scan
// func (e *ErrorHandler) PrintErrorStats() {
// 	e.cacheLock.RLock()
// 	defer e.cacheLock.RUnlock()

// 	var buf strings.Builder
// 	buf.WriteString("=== Error Statistics ===\n\n")

// 	var stats fastcache.Stats
// 	e.cache.UpdateStats(&stats)

// 	indexKey := []byte("index:hosts")
// 	if hostsData := e.cache.Get(nil, indexKey); hostsData != nil {
// 		var hosts []string
// 		json.Unmarshal(hostsData, &hosts)

// 		for _, host := range hosts {
// 			buf.WriteString(fmt.Sprintf("[+] Host: %s\n", host)) // Added host header
// 			hostKey := []byte(fmt.Sprintf("h:%s:e:index", host))

// 			if errorsData := e.cache.Get(nil, hostKey); errorsData != nil {
// 				var errors []string
// 				json.Unmarshal(errorsData, &errors)

// 				for _, errMsg := range errors {
// 					key := []byte(fmt.Sprintf("h:%s:e:%s", host, errMsg))
// 					if data := e.cache.Get(nil, key); data != nil {
// 						var errorStats ErrorStats
// 						if err := json.Unmarshal(data, &errorStats); err != nil {
// 							continue
// 						}

// 						fmt.Fprintf(&buf, "  Error: %s\n", errMsg) // Indented error under host
// 						fmt.Fprintf(&buf, "  Count: %d occurrences\n", errorStats.Count.Load())
// 						fmt.Fprintf(&buf, "  First Seen: %s\n", errorStats.FirstSeen.Format("15:04:05 02 Jan 2006"))
// 						if lastSeen := errorStats.LastSeen.Load(); lastSeen != nil {
// 							fmt.Fprintf(&buf, "  Last Seen: %s\n", lastSeen.Format("15:04:05 02 Jan 2006"))
// 						}

// 						fmt.Fprintln(&buf, "Error Sources:")
// 						errorStats.ErrorSources.Range(func(key, value interface{}) bool {
// 							src := key.(string)
// 							count := value.(int64)
// 							fmt.Fprintf(&buf, "  - %s: %d times\n", src, count)
// 							return true
// 						})

// 						fmt.Fprintln(&buf, "Bypass Modules:")
// 						errorStats.BypassModules.Range(func(key, value interface{}) bool {
// 							module := key.(string)
// 							count := value.(int64)
// 							fmt.Fprintf(&buf, "  - %s: %d times\n", module, count)
// 							return true
// 						})

// 						errorStats.tokensMutex.RLock()
// 						if len(errorStats.DebugTokens) > 0 {
// 							fmt.Fprintln(&buf, "Debug Tokens:")
// 							tokens := errorStats.DebugTokens
// 							if len(tokens) > 5 {
// 								fmt.Fprintf(&buf, "  Showing last 5 of %d tokens:\n", len(tokens))
// 								tokens = tokens[len(tokens)-5:]
// 							}
// 							for _, token := range tokens {
// 								fmt.Fprintf(&buf, "  - %s\n", token)
// 							}
// 						}
// 						errorStats.tokensMutex.RUnlock()

// 						buf.WriteString("\n")
// 					}
// 				}
// 			}
// 			buf.WriteString("\n")
// 		}
// 	}

// 	fmt.Print(buf.String())
// }

// // Reset the error cache
// func (e *ErrorHandler) Reset() {
// 	e.cacheLock.Lock()
// 	defer e.cacheLock.Unlock()
// 	e.cache.Reset()
// }

// // Helper method to maintain the host index
// func (e *ErrorHandler) addToIndex(host, errMsg string) {
// 	// Add to hosts index
// 	indexKey := []byte("index:hosts")
// 	var hosts []string
// 	if data := e.cache.Get(nil, indexKey); data != nil {
// 		json.Unmarshal(data, &hosts)
// 	}
// 	if !slices.Contains(hosts, host) {
// 		hosts = append(hosts, host)
// 		if data, err := json.Marshal(hosts); err == nil {
// 			e.cache.Set(indexKey, data)
// 		}
// 	}

// 	// Add to host errors index
// 	hostKey := []byte(fmt.Sprintf("h:%s:e:index", host))
// 	var errors []string
// 	if data := e.cache.Get(nil, hostKey); data != nil {
// 		json.Unmarshal(data, &errors)
// 	}
// 	if !slices.Contains(errors, errMsg) {
// 		errors = append(errors, errMsg)
// 		if data, err := json.Marshal(errors); err == nil {
// 			e.cache.Set(hostKey, data)
// 		}
// 	}
// }
