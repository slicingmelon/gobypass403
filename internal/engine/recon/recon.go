package recon

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/slicingmelon/go-rawurlparser"
	"github.com/valyala/fasthttp"
)

type ReconService struct {
	cache  *ReconCache
	logger *GB403Logger.Logger
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

func NewReconService() *ReconService {
	dialer := &fasthttp.TCPDialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				switch network {
				case "udp", "udp4", "udp6":
					// Round-robin between multiple resolvers for redundancy
					resolvers := []string{
						"8.8.8.8:53",                // Google
						"1.1.1.1:53",                // Cloudflare
						"9.9.9.9:53",                // Quad9
						"[2001:4860:4860::8888]:53", // Google IPv6
						"[2606:4700:4700::1111]:53", // Cloudflare IPv6
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
		DNSCacheDuration: 5 * time.Minute,
	}

	return &ReconService{
		cache:  NewReconCache(),
		logger: GB403Logger.NewLogger(),
		dialer: dialer,
	}
}

func (s *ReconService) Run(urls []string) error {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	// Track unique hosts to avoid duplicate scans
	uniqueHosts := make(map[string]bool)

	for _, rawURL := range urls {
		parsedURL, err := rawurlparser.RawURLParse(rawURL)
		if err != nil {
			s.logger.LogError("Failed to parse URL %s: %v", rawURL, err)
			continue
		}

		// Skip if we've already processed this host
		if uniqueHosts[parsedURL.Host] {
			continue
		}
		uniqueHosts[parsedURL.Host] = true

		wg.Add(1)
		go func(url string, host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Check if we already have this host in cache
			existingResult, _ := s.cache.Get(host)
			if existingResult == nil {
				existingResult = &ReconResult{
					Hostname:     host,
					IPv4Services: make(map[string]map[string][]string),
					IPv6Services: make(map[string]map[string][]string),
				}
			}

			// Resolve IPs only once per host
			ips, err := s.resolveHost(host)
			if err != nil {
				s.logger.LogError("Failed to resolve host %s: %v", host, err)
				return
			}

			// Initialize service maps if needed
			if existingResult.IPv4Services == nil {
				existingResult.IPv4Services = make(map[string]map[string][]string)
			}
			if existingResult.IPv6Services == nil {
				existingResult.IPv6Services = make(map[string]map[string][]string)
			}

			// Check ports only for the resolved IPs
			portsToCheck := []string{"80", "443"}
			if parsedURL.Port() != "" {
				portsToCheck = append(portsToCheck, parsedURL.Port())
			}

			// Process IPv4
			for _, ip := range ips.IPv4 {
				for _, port := range portsToCheck {
					if scheme := s.probePort(ip, port); scheme != "" {
						if existingResult.IPv4Services[scheme] == nil {
							existingResult.IPv4Services[scheme] = make(map[string][]string)
						}
						existingResult.IPv4Services[scheme][ip] = append(existingResult.IPv4Services[scheme][ip], port)
					}
				}
			}

			// Process IPv6
			for _, ip := range ips.IPv6 {
				for _, port := range portsToCheck {
					if scheme := s.probePort(ip, port); scheme != "" {
						if existingResult.IPv6Services[scheme] == nil {
							existingResult.IPv6Services[scheme] = make(map[string][]string)
						}
						existingResult.IPv6Services[scheme][ip] = append(existingResult.IPv6Services[scheme][ip], port)
					}
				}
			}

			// Update cache
			if err := s.cache.Set(host, existingResult); err != nil {
				s.logger.LogError("Failed to cache results for %s: %v", host, err)
			}
		}(rawURL, parsedURL.Host)
	}

	wg.Wait()
	return nil
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

	// Use DialDualStack to attempt both IPv4 and IPv6
	conn, err := s.dialer.DialDualStackTimeout(addr, 5*time.Second)
	if err != nil {
		s.logger.LogVerbose("Port %s closed for host %s: %v", port, host, err)
		return ""
	}
	defer conn.Close()

	switch port {
	case "80":
		return "http"
	case "443":
		return "https"
	default:
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
