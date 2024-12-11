package probe

import (
	"fmt"
	"sync"

	"github.com/projectdiscovery/gcache"
	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/slicingmelon/go-rawurlparser"
)

// Cache defines the interface for probe result caching
type Cache interface {
	Get(host string) (*ProbeResult, bool)
	Store(host string, result *ProbeResult) error
	UpdateHost(r ProbeResult) error
	Delete(host string)
	Purge()
}

// ProbeResultsCache implements the Cache interface
type ProbeResultsCache struct {
	sync.RWMutex
	hostResults gcache.Cache[string, *ProbeResult]
}

// NewProbeResultsCache creates a new probe results cache
func NewProbeResultsCache() Cache { // Note: Returns interface instead of concrete type
	return &ProbeResultsCache{
		hostResults: gcache.New[string, *ProbeResult](1000).
			LRU().
			Build(),
	}
}

// ProbeResult -- detailed information about a probed URL
type ProbeResult struct {
	Hostname string            // Clean hostname without port
	Ports    map[string]string // map[port]scheme e.g. "80":"http"
	Schemes  []string          // List of unique schemes found
	IPv4     []string          // A records
	IPv6     []string          // AAAA records
	CNAMEs   []string          // CNAME records
}

func (c *ProbeResultsCache) UpdateHost(r ProbeResult) error {
	c.Lock()
	defer c.Unlock()

	// Parse URL to get clean hostname
	parsedURL, err := rawurlparser.RawURLParse(r.Hostname)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %v", err)
	}
	hostname := parsedURL.Hostname()

	logger.Verbose("Updating cache for %s => %s", parsedURL.Host, hostname)

	result, err := c.hostResults.Get(hostname)
	if err != nil {
		// Create new result if host doesn't exist
		result = &ProbeResult{
			Hostname: hostname,
			Ports:    make(map[string]string),
			Schemes:  make([]string, 0),
			IPv4:     r.IPv4,
			IPv6:     r.IPv6,
			CNAMEs:   r.CNAMEs,
		}
	}

	// Update IPs and CNAMEs
	result.IPv4 = MergeUnique(result.IPv4, r.IPv4)
	result.IPv6 = MergeUnique(result.IPv6, r.IPv6)
	result.CNAMEs = MergeUnique(result.CNAMEs, r.CNAMEs)

	// Update ports and schemes
	for port, scheme := range r.Ports {
		result.Ports[port] = scheme
		if !ValidateScheme(result.Schemes, scheme) {
			result.Schemes = append(result.Schemes, scheme)
		}
	}

	logger.Verbose("Final cache entry for host %s:\n"+
		"Hostname: %s\n"+
		"Schemes: %v\n"+
		"Ports: %v\n"+
		"IPv4: %v\n"+
		"IPv6: %v\n"+
		"CNAMEs: %v\n",
		hostname, result.Hostname, result.Schemes, result.Ports, result.IPv4, result.IPv6, result.CNAMEs)

	return c.hostResults.Set(hostname, result)
}

func (c *ProbeResultsCache) Store(host string, result *ProbeResult) error {
	c.Lock()
	defer c.Unlock()
	return c.hostResults.Set(host, result)
}

func (c *ProbeResultsCache) Get(host string) (*ProbeResult, bool) {
	c.RLock()
	defer c.RUnlock()
	result, err := c.hostResults.Get(host)
	return result, err == nil
}

func (c *ProbeResultsCache) Delete(host string) {
	c.Lock()
	defer c.Unlock()
	c.hostResults.Remove(host)
}

func (c *ProbeResultsCache) Purge() {
	c.Lock()
	defer c.Unlock()
	c.hostResults.Purge()
}
