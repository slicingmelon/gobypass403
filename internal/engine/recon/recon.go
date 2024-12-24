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
	Hostname string
	Ports    map[string]string // port -> protocol (80 -> "http")
	IPv4     []string
	IPv6     []string
	CNAMEs   []string
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
	sem := make(chan struct{}, 10) // Limit concurrent operations

	for _, rawURL := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release

			parsedURL, err := rawurlparser.RawURLParse(url)
			if err != nil {
				s.logger.LogError("Failed to parse URL %s: %v", url, err)
				return
			}

			result := &ReconResult{
				Hostname: parsedURL.Host,
				Ports:    make(map[string]string),
			}

			// Resolve IPv4 and IPv6
			ips, err := s.resolveHost(parsedURL.Host)
			if err != nil {
				s.logger.LogError("Failed to resolve %s: %v", parsedURL.Host, err)
			} else {
				result.IPv4 = ips.IPv4
				result.IPv6 = ips.IPv6
				result.CNAMEs = ips.CNAMEs
			}

			// Check ports
			portsToCheck := []string{"80", "443"}
			if parsedURL.Port() != "" {
				portsToCheck = append(portsToCheck, parsedURL.Port())
			}

			for _, port := range portsToCheck {
				proto := s.probePort(parsedURL.Host, port)
				if proto != "" {
					result.Ports[port] = proto
				}
			}

			// Cache results
			if err := s.cache.Set(parsedURL.Host, result); err != nil {
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
