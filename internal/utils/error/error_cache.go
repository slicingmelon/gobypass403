package error

import (
	"encoding/binary"
	"errors"
	"sync/atomic"

	"github.com/VictoriaMetrics/fastcache"
)

// Cache errors
var (
	ErrCacheInit      = errors.New("bypass: cache initialization failed")
	ErrCacheCorrupted = errors.New("bypass: cache data corrupted")
)

// Stats holds error handler statistics
type CacheStats struct {
	Hits   uint64
	Misses uint64
	Resets uint64
}

func NewErrorHandler() *ErrorHandler {
	return &ErrorHandler{
		cache:     fastcache.New(32 * 1024 * 1024),
		maxErrors: 15,
		hostStats: make(map[string]*HostStats), // Initialize the map
		stats:     ErrorStats{},                // Initialize stats
	}
}

func LoadErrorHandler(filePath string) (*ErrorHandler, error) {
	cache, err := fastcache.LoadFromFile(filePath)
	if err != nil {
		return nil, err
	}
	return &ErrorHandler{
		cache:     cache,
		maxErrors: 15,
		hostStats: make(map[string]*HostStats),
		stats:     ErrorStats{},
	}, nil
}

// Rest of cache-related methods...
// incrementErrorCount increases and returns the error count for a host
func (h *ErrorHandler) incrementErrorCount(hostKey []byte) uint32 {
	buf := make([]byte, 4)
	if v := h.cache.Get(buf[:0], hostKey); len(v) == 4 {
		count := binary.LittleEndian.Uint32(v)
		count++
		binary.LittleEndian.PutUint32(buf, count)
		h.cache.Set(hostKey, buf)
		atomic.AddUint64(&h.stats.CacheHits, 1)
		return count
	}

	binary.LittleEndian.PutUint32(buf, 1)
	h.cache.Set(hostKey, buf)
	atomic.AddUint64(&h.stats.CacheMisses, 1)
	return 1
}

// HasErrors checks if a host has any recorded errors
func (h *ErrorHandler) HasErrors(host string) bool {
	return h.cache.Has([]byte(host))
}

// GetErrorCount returns the error count for a host
func (h *ErrorHandler) GetErrorCount(host string) uint32 {
	buf := make([]byte, 4)
	if v := h.cache.Get(buf[:0], []byte(host)); len(v) == 4 {
		return binary.LittleEndian.Uint32(v)
	}
	return 0
}

// Reset error count for a host
func (h *ErrorHandler) Reset(host string) {
	h.cache.Del([]byte(host))
	atomic.AddUint64(&h.stats.CacheResets, 1)
}

// ResetAll removes all error counts
func (h *ErrorHandler) ResetAll() {
	h.cache.Reset()
}

// SaveState saves error handler state to file
func (h *ErrorHandler) SaveState(filePath string) error {
	return h.cache.SaveToFile(filePath)
}

// SaveStateConcurrent saves state using multiple CPU cores
func (h *ErrorHandler) SaveStateConcurrent(filePath string, concurrency int) error {
	return h.cache.SaveToFileConcurrent(filePath, concurrency)
}

// GetStats returns current statistics
func (h *ErrorHandler) GetCacheStats() CacheStats {
	return CacheStats{
		Hits:   atomic.LoadUint64(&h.stats.CacheHits),
		Misses: atomic.LoadUint64(&h.stats.CacheMisses),
		Resets: atomic.LoadUint64(&h.stats.CacheResets),
	}
}

func (h *ErrorHandler) Close() {
	if h.cache != nil {
		h.cache.Reset()
	}
}
