package probe

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gcache"
	"github.com/slicingmelon/go-rawurlparser"
)

// Initialize global cache
var globalProbeURLResults = NewProbeURLResultsCache()

type ProbeService struct {
	cache *ProbeResultsCache
}

// Constructor for the probe service
func NewProbeService() *ProbeService {
	return &ProbeService{
		cache: NewProbeURLResultsCache(),
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

// ProbeResultsCache is a cache for the probing phase
type ProbeResultsCache struct {
	sync.RWMutex
	hostResults gcache.Cache[string, *ProbeResult]
}

func NewProbeURLResultsCache() *ProbeResultsCache {
	return &ProbeResultsCache{
		hostResults: gcache.New[string, *ProbeResult](1000).
			LRU().
			Build(),
	}
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

	LogDebug("[DEBUG] Updating cache for %s => %s", parsedURL.Host, hostname)

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
	result.IPv4 = mergeUnique(result.IPv4, r.IPv4)
	result.IPv6 = mergeUnique(result.IPv6, r.IPv6)
	result.CNAMEs = mergeUnique(result.CNAMEs, r.CNAMEs)

	// Update ports and schemes
	for port, scheme := range r.Ports {
		result.Ports[port] = scheme
		if !validateScheme(result.Schemes, scheme) {
			result.Schemes = append(result.Schemes, scheme)
		}
	}

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

// Make it a method of ProbeService
func (s *ProbeService) FastProbeURLs(urls []string) error {
	if len(urls) == 0 {
		return fmt.Errorf("no URLs provided for validation")
	}

	LogYellow("[+] Starting URL validation for %d URLs\n", len(urls))
	LogVerbose("[VERBOSE] URLs to probe: %v", urls)

	opts := fastdialer.DefaultOptions
	opts.EnableFallback = true
	opts.DialerTimeout = 10 * time.Second
	opts.DialerKeepAlive = 10 * time.Second
	opts.MaxRetries = 3
	opts.HostsFile = true
	opts.ResolversFile = true
	opts.BaseResolvers = []string{
		"1.1.1.1:53", "1.0.0.1:53",
		"8.8.8.8:53", "8.8.4.4:53",
	}
	opts.WithDialerHistory = true
	opts.WithTLSData = true
	opts.CacheType = fastdialer.Disk
	opts.WithCleanup = true
	opts.WithZTLS = false
	opts.DisableZtlsFallback = true
	opts.OnDialCallback = func(hostname, ip string) {
		LogVerbose("[DIALER] Connected to %s (%s)", hostname, ip)
	}
	opts.OnInvalidTarget = func(hostname, ip, port string) {
		LogDebug("[DEBUG] Invalid target: %s (%s:%s)", hostname, ip, port)
	}

	dialer, err := fastdialer.NewDialer(opts)
	if err != nil {
		return fmt.Errorf("failed to create fastdialer: %v", err)
	}
	defer dialer.Close()

	urlChan := make(chan string, len(urls))
	errorChan := make(chan error, len(urls))
	var wg sync.WaitGroup

	// Single worker
	// Single worker
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx := context.TODO()

		for url := range urlChan {
			LogVerbose("Processing URL: %s", url)

			host := url
			if strings.Contains(url, "://") {
				if parsed, err := rawurlparser.RawURLParse(url); err == nil {
					host = parsed.Host
				}
			}

			hostname, specifiedPort, _ := net.SplitHostPort(host)
			if hostname == "" {
				hostname = host
			}

			result := &ProbeResult{
				Hostname: hostname,
				Ports:    make(map[string]string),
				Schemes:  make([]string, 0),
			}

			// Handle differently based on whether it's an IP or domain
			isIP := net.ParseIP(hostname) != nil

			if !isIP {
				// Only do DNS lookup for domains, not IPs
				dnsData, err := dialer.GetDNSData(hostname)
				if err != nil {
					LogDebug("[DEBUG] DNS lookup failed for %s: %v", hostname, err)
					continue
				}
				result.IPv4 = dnsData.A
				result.IPv6 = dnsData.AAAA
				result.CNAMEs = dnsData.CNAME
			} else {
				// For IPs, just add the IP to the IPv4/IPv6 list
				ip := net.ParseIP(hostname)
				if ip.To4() != nil {
					result.IPv4 = []string{hostname}
				} else {
					result.IPv6 = []string{hostname}
				}
			}

			portsToTry := []string{"443", "80"}
			if specifiedPort != "" {
				portsToTry = []string{specifiedPort}
			}

			for _, port := range portsToTry {
				hostPort := net.JoinHostPort(hostname, port)

				// Try TLS first with timeout context
				dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				conn, err := dialer.DialTLS(dialCtx, "tcp", hostPort)
				cancel()

				if err == nil {
					conn.Close()
					result.Ports[port] = "https"
					if !validateScheme(result.Schemes, "https") {
						result.Schemes = append(result.Schemes, "https")
					}
					continue
				}

				// If TLS fails, try plain TCP with timeout
				dialCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
				conn, err = dialer.Dial(dialCtx, "tcp", hostPort)
				cancel()

				if err == nil {
					conn.Close()
					result.Ports[port] = "http"
					if !validateScheme(result.Schemes, "http") {
						result.Schemes = append(result.Schemes, "http")
					}
				}
			}

			// Only update cache if we found any ports
			if len(result.Ports) > 0 {
				if err := s.cache.UpdateHost(*result); err != nil {
					LogError("[ERROR] Failed to update cache for %s: %v", hostname, err)
				}
			} else {
				LogDebug("[DEBUG] No open ports found for %s", hostname)
			}
		}
	}()

	// Feed URLs to the single worker
	for _, url := range urls {
		urlChan <- url
	}
	close(urlChan)

	wg.Wait()
	close(errorChan)

	return nil
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

// Helper function to check if the scheme already exists
func validateScheme(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
