package error

// Custom Error Handler implementing a cache for errors statistics.
// It is used to track the number of errors for better debugging.

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/valyala/fasthttp"
)

const (
	DefaultCacheSizeMB = 32 // MB - kept for compatibility
	MaxDebugTokens     = 5
	maxErrorLength     = 250
)

var (
	instance *ErrorHandler
	once     sync.Once
)

var (
	ErrBodyTooLarge          = fasthttp.ErrBodyTooLarge // "body size exceeds the given limit"
	ErrInvalidResponseHeader = errors.New("invalid header")
	ErrConnForciblyClosedWin = errors.New("wsarecv: An existing connection was forcibly closed by the remote host")
)

var defaultWhitelistedErrorsStr = []string{
	ErrBodyTooLarge.Error(),
	ErrInvalidResponseHeader.Error(),
}

var (
	whitelistErrors = make(map[string]struct{})
	whitelistMutex  sync.RWMutex
)

type ErrorHandler struct {
	cache      *ristretto.Cache[string, map[string]*ErrorStats]
	hostsIndex *ristretto.Cache[string, struct{}]
	hostSet    sync.Map // Track active hosts
	statsLock  sync.RWMutex
}

func NewTokenRing(size int) *TokenRing {
	return &TokenRing{
		tokens: make([]string, 0, size),
		size:   size,
	}
}

func (tr *TokenRing) Add(token string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	if len(tr.tokens) < tr.size {
		tr.tokens = append(tr.tokens, token)
	} else {
		tr.tokens[tr.pos] = token
		tr.pos = (tr.pos + 1) % tr.size
	}
}

func (tr *TokenRing) GetLast(n int) []string {
	tr.mu.RLock()
	defer tr.mu.RUnlock()

	if len(tr.tokens) == 0 {
		return nil
	}

	if n > len(tr.tokens) {
		n = len(tr.tokens)
	}

	result := make([]string, n)
	start := len(tr.tokens)
	if start > tr.size {
		start = tr.pos
	}
	for i := 0; i < n; i++ {
		idx := (start - n + i) % len(tr.tokens)
		if idx < 0 {
			idx += len(tr.tokens)
		}
		result[i] = tr.tokens[idx]
	}
	return result
}

// ErrorContext holds metadata about where/when the error occurred
type ErrorContext struct {
	ErrorSource  string
	Host         string
	BypassModule string
	DebugToken   string
}

// ErrorStats tracks statistics for each error type
type ErrorStats struct {
	Count         atomic.Int64
	FirstSeen     time.Time
	LastSeen      atomic.Value // *time.Time
	ErrorSources  sync.Map     // string -> int64
	BypassModules sync.Map     // string -> int64
	DebugTokens   *TokenRing
}

type RingBuffer struct {
	tokens []string
	size   int
	pos    int
	mu     sync.RWMutex
}

type TokenRing struct {
	tokens []string
	pos    int
	size   int
	mu     sync.RWMutex
}

func NewRingBuffer(size int) *RingBuffer {
	return &RingBuffer{
		tokens: make([]string, size),
		size:   size,
	}
}

func (r *RingBuffer) Add(token string) {
	r.mu.Lock()
	r.tokens[r.pos] = token
	r.pos = (r.pos + 1) % r.size
	r.mu.Unlock()
}

// Optimized error stats creation
func newErrorStats() *ErrorStats {
	now := time.Now()
	stats := &ErrorStats{
		FirstSeen:   now,
		DebugTokens: NewTokenRing(MaxDebugTokens),
	}
	stats.LastSeen.Store(&now)
	return stats
}

// NewErrorHandler creates a new ErrorHandler instance
// cacheSizeMB is the size of the cache in MB
func NewErrorHandler() *ErrorHandler {
	cache, err := ristretto.NewCache(&ristretto.Config[string, map[string]*ErrorStats]{
		NumCounters: 1e7,     // 10M counters
		MaxCost:     1 << 30, // 1GB
		BufferItems: 64,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to create cache: %v", err))
	}

	// Smaller cache for hosts index
	hostsIndex, err := ristretto.NewCache(&ristretto.Config[string, struct{}]{
		NumCounters: 1e5,     // 100K counters
		MaxCost:     1 << 20, // 1MB
		BufferItems: 64,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to create hosts index: %v", err))
	}

	handler := &ErrorHandler{
		cache:      cache,
		hostsIndex: hostsIndex,
	}
	handler.AddWhitelistedErrors(defaultWhitelistedErrorsStr...)
	return handler
}

// GetErrorHandler returns the singleton instance of the ErrorHandler
func GetErrorHandler() *ErrorHandler {
	once.Do(func() {
		instance = NewErrorHandler()
	})
	return instance
}

func ResetInstance() {
	instance = nil
	once = sync.Once{}
}

// AddWhitelistedErrors adds errors to the whitelist
// This is needed as fasthttp returns some errors that are not actual errors..
func (e *ErrorHandler) AddWhitelistedErrors(errors ...string) {
	whitelistMutex.Lock()
	defer whitelistMutex.Unlock()
	for _, err := range errors {
		whitelistErrors[err] = struct{}{}
	}
}

// Quick check to see if the error is whitelisted
func (e *ErrorHandler) IsWhitelistedErrNew(err error) bool {
	if err == nil {
		return true
	}
	errMsg := e.StripErrorMessage(err)
	whitelistMutex.RLock()
	_, exists := whitelistErrors[errMsg]
	whitelistMutex.RUnlock()
	return exists
}

// StripErrorMessage strips the error message to a more readable format
// This is needed as some connection errors include a different port number messing up the cache stats
func (e *ErrorHandler) StripErrorMessage(err error) string {
	errMsg := err.Error()

	// Handle special case first
	if strings.Contains(errMsg, ErrConnForciblyClosedWin.Error()) {
		return ErrConnForciblyClosedWin.Error()
	}

	// Truncate long error messages
	if len(errMsg) > maxErrorLength {
		return errMsg[:maxErrorLength] + "..."
	}

	return errMsg
}

// HandleError handles the error and returns nil if it's whitelisted
// Example usage: when error needs to be handled
//
//	if handledErr := .HandleError(err, errCtx); handledErr != nil {
//	    return fmt.Errorf("custom handling: %v", handledErr)
//	}
func (e *ErrorHandler) HandleError(err error, ctx ErrorContext) error {
	if err == nil || e.IsWhitelistedErrNew(err) {
		return nil
	}

	host := "host:" + ctx.Host
	e.hostSet.Store(host, struct{}{}) // Track the host
	errMsg := e.StripErrorMessage(err)

	// Add to hosts index
	e.hostsIndex.Set(host, struct{}{}, 1)
	e.hostsIndex.Wait()

	e.statsLock.Lock()
	defer e.statsLock.Unlock()

	// Get or create host entry
	var hostStats map[string]*ErrorStats
	if val, found := e.cache.Get(host); found {
		hostStats = val
	} else {
		hostStats = make(map[string]*ErrorStats)
		e.cache.Set(host, hostStats, 1)
		e.cache.Wait()
	}

	// Get or create error stats
	stats, exists := hostStats[errMsg]
	if !exists {
		stats = newErrorStats()
		hostStats[errMsg] = stats
		e.cache.Set(host, hostStats, 1)
		e.cache.Wait()
	}

	// Rest of the code remains the same since ErrorStats has its own sync primitives
	stats.Count.Add(1)
	now := time.Now()
	stats.LastSeen.Store(&now)

	if src := ctx.ErrorSource; src != "" {
		if val, ok := stats.ErrorSources.Load(src); ok {
			stats.ErrorSources.Store(src, val.(int64)+1)
		} else {
			stats.ErrorSources.Store(src, int64(1))
		}
	}

	if mod := ctx.BypassModule; mod != "" {
		if val, ok := stats.BypassModules.Load(mod); ok {
			stats.BypassModules.Store(mod, val.(int64)+1)
		} else {
			stats.BypassModules.Store(mod, int64(1))
		}
	}

	if len(ctx.DebugToken) > 0 {
		stats.DebugTokens.Add(ctx.DebugToken)
	}

	return err
}

// HandleErrorAndContinue handles the error and returns nil if it's whitelisted
// Example usage when error needs to be handled but the code must continue
// return  errorHandler.HandleErrorAndContinue(err, errCtx)
func (e *ErrorHandler) HandleErrorAndContinue(err error, ctx ErrorContext) error {
	if err := e.HandleError(err, ctx); err == nil {
		return nil
	}
	return err
}

// PrintErrorStats prints the error stats
// call this anytime!
func (e *ErrorHandler) PrintErrorStats() {
	var buf strings.Builder
	buf.WriteString("=== Error Statistics ===\n\n")

	// Get all hosts from index
	for _, host := range e.getHosts() {
		// Get host stats from cache
		if hostStats, found := e.cache.Get(host); found {
			buf.WriteString(fmt.Sprintf("[+] Host: %s\n", strings.TrimPrefix(host, "host:")))

			// Print each error for this host
			for errMsg, stats := range hostStats {
				fmt.Fprintf(&buf, "  Error: %s\n", errMsg)
				fmt.Fprintf(&buf, "  Count: %d occurrences\n", stats.Count.Load())
				fmt.Fprintf(&buf, "  First Seen: %s\n", stats.FirstSeen.Format("15:04:05 02 Jan 2006"))
				if lastSeen, ok := stats.LastSeen.Load().(*time.Time); ok {
					fmt.Fprintf(&buf, "  Last Seen: %s\n", lastSeen.Format("15:04:05 02 Jan 2006"))
				}

				// Print error sources
				buf.WriteString("  Error Sources:\n")
				stats.ErrorSources.Range(func(key, value any) bool {
					fmt.Fprintf(&buf, "    - %s: %d times\n", key.(string), value.(int64))
					return true
				})

				// Print bypass modules
				buf.WriteString("  Bypass Modules:\n")
				stats.BypassModules.Range(func(key, value any) bool {
					fmt.Fprintf(&buf, "    - %s: %d times\n", key.(string), value.(int64))
					return true
				})

				// Print debug tokens
				tokens := stats.DebugTokens.GetLast(5)
				if len(tokens) > 0 {
					buf.WriteString("  Debug Tokens:\n")
					if len(tokens) == MaxDebugTokens {
						fmt.Fprintf(&buf, "    Showing last %d tokens:\n", MaxDebugTokens)
					}
					for _, token := range tokens {
						fmt.Fprintf(&buf, "    - %s\n", token)
					}
				}
				buf.WriteString("\n")
			}
			buf.WriteString("\n")
		}
	}

	fmt.Print(buf.String())
}

func (e *ErrorHandler) getHosts() []string {
	var hosts []string
	e.hostSet.Range(func(key, _ any) bool {
		hosts = append(hosts, key.(string))
		return true
	})
	return hosts
}

func (e *ErrorHandler) Reset() {
	e.statsLock.Lock()
	defer e.statsLock.Unlock()

	e.cache.Clear()
	e.hostsIndex.Clear()
	e.hostSet = sync.Map{} // Reset host tracking
}
