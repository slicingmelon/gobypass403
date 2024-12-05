package main

import (
	"fmt"
	"sync"

	"github.com/projectdiscovery/gcache"
	"github.com/projectdiscovery/goflags"
	customport "github.com/projectdiscovery/httpx/common/customports"
	"github.com/projectdiscovery/httpx/runner"
	"github.com/slicingmelon/go-rawurlparser"
)

// Initialize global cache
var globalHttpxResults = NewHttpxResultsCache()

// HttpxResult -- detailed information about a probed URL
type HttpxResult struct {
	Hostname string            // Base hostname without port (extracted from URL)
	Ports    map[string]string // Map of port -> scheme (e.g., "80" -> "http", "443" -> "https")
	Schemes  []string          // Available schemes (http, https)
	IPv4     []string          // List of IPv4 addresses
	IPv6     []string          // List of IPv6 addresses
	CNAMEs   []string          // List of CNAMEs
}

// HttpxResultsCache is a cache for the probing phase
type HttpxResultsCache struct {
	sync.RWMutex
	hostResults gcache.Cache[string, *HttpxResult]
}

func NewHttpxResultsCache() *HttpxResultsCache {
	return &HttpxResultsCache{
		hostResults: gcache.New[string, *HttpxResult](1000).
			LRU().
			Build(),
	}
}

// Helper function to check if the scheme already exists
func validateScheme(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (c *HttpxResultsCache) UpdateHost(r runner.Result) error {
	c.Lock()
	defer c.Unlock()

	// Parse URL to get clean hostname
	parsedURL, err := rawurlparser.RawURLParse(r.URL)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %v", err)
	}
	hostname := parsedURL.Hostname()

	LogDebug("[DEBUG] Updating cache for %s => %s, scheme: %s, port: %s", parsedURL.Host, hostname, r.Scheme, r.Port)

	result, err := c.hostResults.Get(hostname)
	if err != nil {
		// Create new result if host doesn't exist
		result = &HttpxResult{
			Hostname: hostname,
			Ports:    make(map[string]string),
			Schemes:  make([]string, 0),
			IPv4:     r.A,
			IPv6:     r.AAAA,
			CNAMEs:   r.CNAMEs,
		}
	}

	// Always update schemes based on port-scheme mapping
	if r.Port != "" && r.Scheme != "" {
		result.Ports[r.Port] = r.Scheme
		if !validateScheme(result.Schemes, r.Scheme) {
			result.Schemes = append(result.Schemes, r.Scheme)
			LogVerbose("[VERBOSE] Added new scheme %s for host %s", r.Scheme, hostname)
		}
	}

	// Update IPs and CNAMEs
	result.IPv4 = mergeUnique(result.IPv4, r.A)
	result.IPv6 = mergeUnique(result.IPv6, r.AAAA)
	result.CNAMEs = mergeUnique(result.CNAMEs, r.CNAMEs)

	// Fix: Changed the debug message format to be clearer
	LogDebug("[DEBUG] Final cache entry for host %s:\n"+
		"Hostname: %s\n"+
		"Schemes: %v\n"+
		"Ports: %v\n"+
		"IPv4: %v\n"+
		"IPv6: %v\n"+
		"CNAMEs: %v\n",
		hostname, result.Hostname, result.Schemes, result.Ports, result.IPv4, result.IPv6, result.CNAMEs)

	return c.hostResults.Set(hostname, result)
}

// Helper function to merge strings without duplicates
func mergeUnique(existing, new []string) []string {
	seen := make(map[string]bool)
	merged := make([]string, 0)

	// Add existing items
	for _, item := range existing {
		if !seen[item] {
			seen[item] = true
			merged = append(merged, item)
		}
	}

	// Add new items
	for _, item := range new {
		if !seen[item] {
			seen[item] = true
			merged = append(merged, item)
		}
	}

	return merged
}

func (c *HttpxResultsCache) Store(host string, result *HttpxResult) error {
	c.Lock()
	defer c.Unlock()
	return c.hostResults.Set(host, result)
}

func (c *HttpxResultsCache) Get(host string) (*HttpxResult, bool) {
	c.RLock()
	defer c.RUnlock()
	result, err := c.hostResults.Get(host)
	return result, err == nil
}

func (c *HttpxResultsCache) Delete(host string) {
	c.Lock()
	defer c.Unlock()
	c.hostResults.Remove(host)
}

func (c *HttpxResultsCache) Purge() {
	c.Lock()
	defer c.Unlock()
	c.hostResults.Purge()
}

// ValidateURLsWithHttpx probes URLs and returns detailed information
func ValidateURLsWithHttpx(urls []string) error {
	if len(urls) == 0 {
		return fmt.Errorf("no URLs provided for validation")
	}

	LogYellow("[+] Starting URL validation for %d URLs\n", len(urls))
	LogVerbose("[VERBOSE] URLs to probe: %v", urls)

	// Create base options template
	baseOptions := runner.Options{
		Methods:          "HEAD",
		RandomAgent:      true,
		NoFallback:       false,
		NoFallbackScheme: true,
		Threads:          5,
		ProbeAllIPS:      true,
		OutputIP:         true,
		OutputCName:      true,
		Timeout:          30,
		Retries:          5,
		ZTLS:             true,
		Debug:            config.Debug,
		DebugRequests:    true,
		DebugResponse:    true,
		Resolvers: []string{
			"1.1.1.1:53", "1.0.0.1:53",
			"9.9.9.10:53", "8.8.4.4:53",
		},
	}

	var wg sync.WaitGroup
	workers := 2 // Number of concurrent workers
	urlChan := make(chan string, len(urls))

	// Error channel to collect errors from workers
	errorChan := make(chan error, len(urls))

	// Start workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for url := range urlChan {
				LogVerbose("[Worker-%d] Processing URL: %s", id, url)

				// Create a new options instance for this URL
				options := baseOptions

				// Parse URL to check for custom port
				parsedURL, err := rawurlparser.RawURLParse(url)
				if err != nil {
					errorChan <- fmt.Errorf("[Worker-%d] failed to parse URL %s: %v", id, url, err)
					continue
				}

				// Initialize custom ports
				customPorts := customport.CustomPorts{}
				if err := customPorts.Set("http:80,https:443"); err != nil {
					errorChan <- fmt.Errorf("[Worker-%d] failed to set default ports: %v", id, err)
					continue
				}

				// Add custom port if present in URL
				if parsedURL.Port() != "" {
					if err := customPorts.Set(fmt.Sprintf("http:%s,https:%s", parsedURL.Port(), parsedURL.Port())); err != nil {
						errorChan <- fmt.Errorf("[Worker-%d] failed to set custom port %s: %v", id, parsedURL.Port(), err)
						continue
					}
				}

				options.CustomPorts = customPorts
				LogDebug("[Worker-%d] Using custom ports for %s: %v", id, url, customPorts)

				options.InputTargetHost = goflags.StringSlice([]string{url})

				var mu sync.Mutex
				options.OnResult = func(r runner.Result) {
					mu.Lock()
					defer mu.Unlock()

					if r.Err != nil {
						LogVerbose("[WARN] Error processing %s: %v", r.URL, r.Err)
						return
					}
					LogDebug("[DEBUG] Successfully processed %s", r.URL)

					if err := globalHttpxResults.UpdateHost(r); err != nil {
						LogError("[ERROR] Failed to update host cache: %v", err)
					} else {
						LogVerbose("[SUCCESS] Updated cache for %s", r.URL)
					}
				}

				// Create a new runner for this URL
				httpxRunner, err := runner.New(&options)
				if err != nil {
					errorChan <- fmt.Errorf("[Worker-%d] failed to create httpx runner for %s: %v", id, url, err)
					continue
				}

				// Run enumeration for this URL
				LogVerbose("[Worker-%d] Starting httpx enumeration for %s", id, url)
				httpxRunner.RunEnumeration()
				httpxRunner.Close()
				LogVerbose("[Worker-%d] Completed httpx enumeration for %s", id, url)
			}
		}(i)
	}

	// Feed URLs to workers
	for _, url := range urls {
		urlChan <- url
	}
	close(urlChan)

	// Wait for all workers to finish
	wg.Wait()
	close(errorChan)

	// Check for any errors
	var errors []error
	for err := range errorChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return fmt.Errorf("encountered %d errors during URL validation: %v", len(errors), errors)
	}

	return nil
}
