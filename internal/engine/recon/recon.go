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

	for _, rawURL := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			parsedURL, err := rawurlparser.RawURLParse(url)
			if err != nil {
				s.logger.LogError("Failed to parse URL %s: %v", url, err)
				return
			}

			// Check if we already have this host in cache
			existingResult, _ := s.cache.Get(parsedURL.Host)
			if existingResult == nil {
				existingResult = &ReconResult{
					Hostname:     parsedURL.Host,
					IPv4Services: make(map[string]map[string][]string),
					IPv6Services: make(map[string]map[string][]string),
				}
			}

			result := &ReconResult{
				Hostname:     parsedURL.Host,
				IPv4Services: make(map[string]map[string][]string),
				IPv6Services: make(map[string]map[string][]string),
			}

			// Check if the host is an IP address
			ipBytes := []byte(parsedURL.Host)
			ip := make(net.IP, net.IPv4len)
			ip, err = fasthttp.ParseIPv4(ip, ipBytes)
			if err == nil {
				// IPv4 address
				result.IPv4Services["http"] = make(map[string][]string)
				result.IPv6Services["https"] = make(map[string][]string)
				ipStr := ip.String()
				portsToCheck := []string{"80", "443"}
				if parsedURL.Port() != "" {
					portsToCheck = append(portsToCheck, parsedURL.Port())
				}

				for _, port := range portsToCheck {
					if scheme := s.probePort(ipStr, port); scheme != "" {
						if result.IPv4Services[scheme] == nil {
							result.IPv4Services[scheme] = make(map[string][]string)
						}
						result.IPv4Services[scheme][ipStr] = append(result.IPv4Services[scheme][ipStr], port)
					}
				}
			} else {
				// Try IPv6 or hostname
				ip := net.ParseIP(parsedURL.Host)
				if ip != nil && ip.To4() == nil {
					// IPv6 address
					result.IPv6Services["http"] = make(map[string][]string)
					result.IPv6Services["https"] = make(map[string][]string)
					ipStr := ip.String()
					portsToCheck := []string{"80", "443"}
					if parsedURL.Port() != "" {
						portsToCheck = append(portsToCheck, parsedURL.Port())
					}

					for _, port := range portsToCheck {
						if scheme := s.probePort(ipStr, port); scheme != "" {
							if result.IPv6Services[scheme] == nil {
								result.IPv6Services[scheme] = make(map[string][]string)
							}
							result.IPv6Services[scheme][ipStr] = append(result.IPv6Services[scheme][ipStr], port)
						}
					}
				} else {
					// Regular hostname handling (existing code)
					ips, err := s.resolveHost(parsedURL.Host)
					if err != nil {
						s.logger.LogError("Failed to resolve %s: %v", parsedURL.Host, err)
						return
					}
					result.CNAMEs = ips.CNAMEs

					// Initialize maps for both schemes
					result.IPv4Services["http"] = make(map[string][]string)
					result.IPv4Services["https"] = make(map[string][]string)
					result.IPv6Services["http"] = make(map[string][]string)
					result.IPv6Services["https"] = make(map[string][]string)

					portsToCheck := []string{"80", "443"}
					if parsedURL.Port() != "" {
						portsToCheck = append(portsToCheck, parsedURL.Port())
					}

					// Check IPv4
					for _, ip := range ips.IPv4 {
						for _, port := range portsToCheck {
							if scheme := s.probePort(ip, port); scheme != "" {
								if result.IPv4Services[scheme] == nil {
									result.IPv4Services[scheme] = make(map[string][]string)
								}
								result.IPv4Services[scheme][ip] = append(result.IPv4Services[scheme][ip], port)
							}
						}
					}

					// Check IPv6
					for _, ip := range ips.IPv6 {
						for _, port := range portsToCheck {
							if scheme := s.probePort(ip, port); scheme != "" {
								if result.IPv6Services[scheme] == nil {
									result.IPv6Services[scheme] = make(map[string][]string)
								}
								result.IPv6Services[scheme][ip] = append(result.IPv6Services[scheme][ip], port)
							}
						}
					}
				}
			}

			// Same for IPv4
			for scheme, ips := range result.IPv4Services {
				for ip, ports := range ips {
					if existingResult.IPv4Services[scheme] == nil {
						existingResult.IPv4Services[scheme] = make(map[string][]string)
					}
					// Merge ports without duplicates
					existingPorts := existingResult.IPv4Services[scheme][ip]
					for _, port := range ports {
						if !contains(existingPorts, port) {
							existingPorts = append(existingPorts, port)
						}
					}
					existingResult.IPv4Services[scheme][ip] = existingPorts
				}
			}

			// Same for IPv6
			for scheme, ips := range result.IPv6Services {
				for ip, ports := range ips {
					if existingResult.IPv6Services[scheme] == nil {
						existingResult.IPv6Services[scheme] = make(map[string][]string)
					}
					existingPorts := existingResult.IPv6Services[scheme][ip]
					for _, port := range ports {
						if !contains(existingPorts, port) {
							existingPorts = append(existingPorts, port)
						}
					}
					existingResult.IPv6Services[scheme][ip] = existingPorts
				}
			}

			if err := s.cache.Set(parsedURL.Host, existingResult); err != nil {
				s.logger.LogError("Failed to cache results for %s: %v", parsedURL.Host, err)
			}
		}(rawURL)
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
