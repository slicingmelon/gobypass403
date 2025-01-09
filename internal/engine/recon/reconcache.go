package recon

import (
	"encoding/json"
	"sync"

	"github.com/VictoriaMetrics/fastcache"
)

type ReconCache struct {
	cache *fastcache.Cache
	mu    sync.RWMutex
}

func NewReconCache() *ReconCache {
	return &ReconCache{
		cache: fastcache.New(32 * 1024 * 1024), // 32MB cache
	}
}

func (c *ReconCache) Set(hostname string, result *ReconResult) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := json.Marshal(result)
	if err != nil {
		return err
	}

	c.cache.Set([]byte(hostname), data)
	return nil
}

func (c *ReconCache) Get(hostname string) (*ReconResult, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	data := c.cache.Get(nil, []byte(hostname))
	if data == nil {
		return nil, nil
	}

	var result ReconResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return &result, nil
}
