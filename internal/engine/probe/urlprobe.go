package probe

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/slicingmelon/go-rawurlparser"
)

// Initialize global cache
//var globalProbeURLResults = NewProbeURLResultsCache()

type ProbeService struct {
	cache  Cache
	logger *GB403Logger.Logger
}

// Constructor for the probe service//
// NewProbeService creates a new probe service
func NewProbeService() *ProbeService {
	return &ProbeService{
		cache:  NewProbeResultsCache(),
		logger: GB403Logger.NewLogger(),
	}
}

// GetCache returns the probe cache
func (s *ProbeService) GetCache() Cache {
	return s.cache
}

// Make it a method of ProbeService
func (s *ProbeService) FastProbeURLs(urls []string) error {
	if len(urls) == 0 {
		return fmt.Errorf("no URLs provided for validation")
	}

	s.logger.LogVerbose("[+] Starting URL validation for %d URLs\n", len(urls))
	s.logger.LogVerbose("[VERBOSE] URLs to probe: %v", urls)

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
		s.logger.LogVerbose("[DIALER] Connected to %s (%s)", hostname, ip)
	}
	opts.OnInvalidTarget = func(hostname, ip, port string) {
		s.logger.LogDebug("[DEBUG] Invalid target: %s (%s:%s)", hostname, ip, port)
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
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx := context.TODO()

		for url := range urlChan {
			s.logger.LogVerbose("Processing URL: %s", url)

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
					s.logger.LogDebug("[DEBUG] DNS lookup failed for %s: %v", hostname, err)
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
					if !ValidateScheme(result.Schemes, "https") {
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
					if !ValidateScheme(result.Schemes, "http") {
						result.Schemes = append(result.Schemes, "http")
					}
				}
			}

			// Only update cache if we found any ports
			if len(result.Ports) > 0 {
				if err := s.cache.UpdateHost(*result); err != nil {
					s.logger.LogError("Failed to update cache for %s: %v", hostname, err)
				}
			} else {
				s.logger.LogVerbose("No open ports found for %s", hostname)
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
func MergeUnique(existing, new []string) []string {
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
func ValidateScheme(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
