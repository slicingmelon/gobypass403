package recon

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/slicingmelon/go-rawurlparser"
	"github.com/valyala/fasthttp"
)

type ReconService struct {
	cache  *ReconCache
	logger GB403Logger.ILogger
	dialer *fasthttp.TCPDialer
}

type ReconResult struct {
	Hostname     string
	IPv4Services map[string]map[string][]string // scheme -> ipv4 -> []ports
	IPv6Services map[string]map[string][]string // scheme -> ipv6 -> []ports
	CNAMEs       []string
}

type IPAddrs struct {
	IPv4   []string
	IPv6   []string
	CNAMEs []string
}

func (s *ReconService) processHost(host string) error {
	if net.ParseIP(host) != nil {
		s.handleIP(host)
	} else {
		s.handleDomain(host)
	}
	return nil
}

func NewReconService(logger GB403Logger.ILogger) *ReconService {
	if logger == nil {
		logger = GB403Logger.NewLogger()
	}

	dialer := &fasthttp.TCPDialer{
		Concurrency:      2048,
		DNSCacheDuration: 15 * time.Minute,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: 5 * time.Second,
					// Add connection pooling
					KeepAlive: 30 * time.Second,
					DualStack: true,
				}
				switch network {
				case "udp", "udp4", "udp6":
					// Round-robin between multiple resolvers for redundancy
					resolvers := []string{
						"8.8.8.8:53",                // Google
						"1.1.1.1:53",                // Cloudflare
						"9.9.9.9:53",                // Quad9
						"208.67.222.222:53",         // OpenDNS
						"8.8.4.4:53",                // Google Secondary
						"1.0.0.1:53",                // Cloudflare Secondary
						"[2001:4860:4860::8888]:53", // Google IPv6
						"[2606:4700:4700::1111]:53", // Cloudflare IPv6
						"[2620:fe::fe]:53",          // Quad9 IPv6
						"[2620:0:ccc::2]:53",        // OpenDNS IPv6
					}
					// Try each resolver until one works
					for _, resolver := range resolvers {
						if conn, err := d.DialContext(ctx, "udp", resolver); err == nil {
							return conn, nil
						}
					}
				}
				return d.DialContext(ctx, network, address)
			},
		},
	}

	return &ReconService{
		cache:  NewReconCache(),
		logger: logger,
		dialer: dialer,
	}
}

func (s *ReconService) Run(urls []string) error {
	maxWorkers := 50
	jobs := make(chan string, len(urls))
	results := make(chan error, len(urls))

	// Process unique hosts first to avoid duplicate work
	uniqueHosts := make(map[string]bool)
	for _, url := range urls {
		if parsedURL, err := rawurlparser.RawURLParse(url); err == nil {
			uniqueHosts[parsedURL.Host] = true
		}
	}

	// Start workers before feeding jobs
	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				if err := s.processHost(host); err != nil {
					select {
					case results <- fmt.Errorf("host %s: %v", host, err):
					default:
					}
				}
			}
		}()
	}

	// Feed all jobs at once
	for host := range uniqueHosts {
		jobs <- host
	}
	close(jobs)

	// Wait and process results
	go func() {
		wg.Wait()
		close(results)
	}()

	for err := range results {
		if err != nil {
			s.logger.LogError("%v", err)
		}
	}

	return nil
}

func (s *ReconService) handleIP(ip string) {
	result := &ReconResult{
		Hostname:     ip,
		IPv4Services: make(map[string]map[string][]string),
		IPv6Services: make(map[string]map[string][]string),
	}

	// Determine service map based on IP version
	services := result.IPv4Services
	if strings.Contains(ip, ":") {
		services = result.IPv6Services
		s.logger.LogVerbose("Handling IPv6: %s", ip)
	} else {
		s.logger.LogVerbose("Handling IPv4: %s", ip)
	}

	// Check both ports and store all available schemes
	for _, port := range []string{"80", "443"} {
		s.logger.LogVerbose("Probing %s:%s", ip, port)
		if scheme := s.probePort(ip, port); scheme != "" {
			s.logger.LogVerbose("Found open port %s:%s -> %s", ip, port, scheme)
			if services[scheme] == nil {
				services[scheme] = make(map[string][]string)
			}
			services[scheme][ip] = append(services[scheme][ip], port)
		}
	}

	s.logger.LogVerbose("Caching result for %s: IPv4=%v, IPv6=%v",
		ip, result.IPv4Services, result.IPv6Services)
	s.cache.Set(ip, result)
}

func (s *ReconService) handleDomain(host string) {
	ips, err := s.resolveHost(host)
	if err != nil {
		s.logger.LogError("Failed to resolve host %s: %v", host, err)
		return
	}

	result := &ReconResult{
		Hostname:     host,
		IPv4Services: make(map[string]map[string][]string),
		IPv6Services: make(map[string]map[string][]string),
		CNAMEs:       ips.CNAMEs,
	}

	// Port scan IPv4 addresses
	for _, ip := range ips.IPv4 {
		for _, port := range []string{"80", "443"} {
			if scheme := s.probePort(ip, port); scheme != "" {
				if result.IPv4Services[scheme] == nil {
					result.IPv4Services[scheme] = make(map[string][]string)
				}
				result.IPv4Services[scheme][ip] = append(result.IPv4Services[scheme][ip], port)
			}
		}
	}

	// Port scan IPv6 addresses
	for _, ip := range ips.IPv6 {
		for _, port := range []string{"80", "443"} {
			if scheme := s.probePort(ip, port); scheme != "" {
				if result.IPv6Services[scheme] == nil {
					result.IPv6Services[scheme] = make(map[string][]string)
				}
				result.IPv6Services[scheme][ip] = append(result.IPv6Services[scheme][ip], port)
			}
		}
	}

	s.cache.Set(host, result)
}

func (s *ReconService) resolveHost(hostname string) (*IPAddrs, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := &IPAddrs{}

	// Use LookupIPAddr to get both IPv4 and IPv6
	ips, err := s.dialer.Resolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return nil, err
	}

	// Separate IPv4 and IPv6 addresses
	for _, ip := range ips {
		if ip4 := ip.IP.To4(); ip4 != nil {
			result.IPv4 = append(result.IPv4, ip4.String())
		} else {
			result.IPv6 = append(result.IPv6, ip.IP.String())
		}
	}

	// Get CNAMEs
	if cname, err := net.LookupCNAME(hostname); err == nil && cname != "" {
		result.CNAMEs = append(result.CNAMEs, cname)
	}

	return result, nil
}

func (s *ReconService) probePort(host, port string) string {
	addr := net.JoinHostPort(host, port)
	s.logger.LogVerbose("Attempting to probe %s", addr)

	conn, err := s.dialer.DialDualStackTimeout(addr, 5*time.Second)
	if err != nil {
		s.logger.LogVerbose("Port %s closed for host %s: %v", port, host, err)
		return ""
	}
	defer conn.Close()
	s.logger.LogVerbose("Successfully connected to %s", addr)

	switch port {
	case "80":
		s.logger.LogVerbose("Port 80 open on %s -> http", host)
		return "http"
	case "443":
		s.logger.LogVerbose("Port 443 open on %s -> https", host)
		return "https"
	default:
		s.logger.LogVerbose("Custom port %s open on %s, probing for HTTP/HTTPS", port, host)
		// For custom ports, try HTTP first then HTTPS
		req := fasthttp.AcquireRequest()
		defer fasthttp.ReleaseRequest(req)
		resp := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseResponse(resp)

		client := &fasthttp.Client{
			Dial: s.dialer.DialDualStack,
		}

		// Try HTTP first
		req.SetRequestURI(fmt.Sprintf("http://%s", addr))
		if err := client.DoTimeout(req, resp, 5*time.Second); err == nil {
			return "http"
		}

		// Try HTTPS
		req.URI().SetScheme("https")
		if err := client.DoTimeout(req, resp, 5*time.Second); err == nil {
			return "https"
		}

		return "unknown"
	}
}

// Helper function to check if a port exists in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (s *ReconService) GetCache() *ReconCache {
	return s.cache
}
