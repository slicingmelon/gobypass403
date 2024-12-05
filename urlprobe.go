package main

import (
	"fmt"
	"sync"

	"github.com/projectdiscovery/gcache"
	"github.com/projectdiscovery/goflags"
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
			Schemes:  []string{r.Scheme},
			IPv4:     r.A,
			IPv6:     r.AAAA,
			CNAMEs:   r.CNAMEs,
		}
		// Add port-scheme mapping if port is provided
		if r.Port != "" {
			result.Ports[r.Port] = r.Scheme
			LogVerbose("[VERBOSE] Added port mapping %s -> %s", r.Port, r.Scheme)
		}
	} else {
		// Update existing result
		// Add scheme if it doesn't exist
		if !validateScheme(result.Schemes, r.Scheme) {
			LogVerbose("[VERBOSE] Adding new scheme %s for host %s", r.Scheme, hostname)
			result.Schemes = append(result.Schemes, r.Scheme)
		}

		// Update port-scheme mapping
		if r.Port != "" {
			if existingScheme, ok := result.Ports[r.Port]; ok {
				if existingScheme != r.Scheme {
					LogVerbose("[VERBOSE] Port %s scheme updated: %s -> %s",
						r.Port, existingScheme, r.Scheme)
				}
			} else {
				LogVerbose("[VERBOSE] Added new port mapping %s -> %s", r.Port, r.Scheme)
			}
			result.Ports[r.Port] = r.Scheme
		}

		// Update IPs and CNAMEs
		result.IPv4 = mergeUnique(result.IPv4, r.A)
		result.IPv6 = mergeUnique(result.IPv6, r.AAAA)
		result.CNAMEs = mergeUnique(result.CNAMEs, r.CNAMEs)
	}

	LogDebug("[DEBUG] Final cache entry for %s://%s:\n"+
		"Host: %s\n"+
		"Schemes: %v\n"+
		"Ports: %v\n"+
		"IPv4: %v\n"+
		"IPv6: %v\n"+
		"CNAMEs: %v",
		parsedURL.Scheme+"://"+parsedURL.Host, hostname, result.Schemes, result.Ports, result.IPv4, result.IPv6, result.CNAMEs)

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
	LogDebug("[DEBUG] Starting URL validation for %d URLs", len(urls))

	var wg sync.WaitGroup
	errChan := make(chan error, len(urls))

	// Process URLs in batches
	batchSize := 5
	for i := 0; i < len(urls); i += batchSize {
		end := i + batchSize
		if end > len(urls) {
			end = len(urls)
		}
		batch := urls[i:end]

		wg.Add(1)
		go func(urlBatch []string) {
			defer wg.Done()

			options := runner.Options{
				Methods:          "HEAD",
				InputTargetHost:  goflags.StringSlice(urlBatch),
				RandomAgent:      true,
				NoFallback:       true,
				NoFallbackScheme: true,
				Threads:          1,
				ProbeAllIPS:      false,
				OutputIP:         true,
				OutputCName:      true,
				Timeout:          30,
				Retries:          3,
				ZTLS:             true,
				Debug:            config.Debug,
				Resolvers: []string{
					"1.1.1.1:53", "1.0.0.1:53",
					"9.9.9.10:53", "8.8.4.4:53",
				},
				OnResult: func(r runner.Result) {
					if r.Err != nil || r.URL == "" {
						LogVerbose("Skipping invalid result: %v", r.Err)
						return
					}

					// Parse URL to get the actual hostname
					parsedURL, err := rawurlparser.RawURLParse(r.URL)
					if err != nil {
						LogVerbose("[ValidateURLsWithHttpx->RawURLParse] Failed to parse URL: %v", err)
						return
					}

					LogVerbose("[ValidateURLsWithHttpx->OnResult] Processing result:\n"+
						"URL: %s\n"+
						"Parsed Host: %s\n"+
						"IP: %s\n"+
						"Port: %s\n"+
						"Scheme: %v\n"+
						"IPs: %v\n"+
						"CNAMEs: %v\n",
						r.URL, parsedURL.Host, r.Host, r.Port, r.Scheme, r.A, r.CNAMEs)

					if err := globalHttpxResults.UpdateHost(r); err != nil {
						LogVerbose("Failed to update host cache: %v", err)
					}
				},
			}

			httpxRunner, err := runner.New(&options)
			if err != nil {
				errChan <- fmt.Errorf("failed to create httpx runner: %v", err)
				return
			}
			defer httpxRunner.Close()

			LogVerbose("Starting httpx enumeration for batch")
			httpxRunner.RunEnumeration()
		}(batch)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(errChan)

	// Check for any errors
	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}
