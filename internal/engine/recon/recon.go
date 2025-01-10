package recon

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/slicingmelon/go-rawurlparser"
	"github.com/valyala/fasthttp"
)

type ReconService struct {
	cache  *ReconCache
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

func NewReconService() *ReconService {
	dialer := &fasthttp.TCPDialer{
		Concurrency:      1024,
		DNSCacheDuration: 15 * time.Minute,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: 5 * time.Second,
					// Add connection pooling
					KeepAlive: 30 * time.Second,
				}

				// Extract host from address (removes port)
				host := strings.Split(address, ":")[0]

				// Try local resolution first
				if ip := resolveFromHostsFile(host); ip != "" {
					GB403Logger.Verbose().
						Metadata("resolveFromHosts()", "success").
						Msgf("Resolved %s to %s from hosts file", host, ip)
					return d.DialContext(ctx, network, ip+":53")
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
		dialer: dialer,
	}
}

// Simple hosts file parser
func resolveFromHostsFile(host string) string {
	// Handle localhost explicitly
	if host == "localhost" {
		return "127.0.0.1"
	}

	// Read /etc/hosts file
	hostsFile := "/etc/hosts"
	if runtime.GOOS == "windows" {
		hostsFile = `C:\Windows\System32\drivers\etc\hosts`
	}

	file, err := os.Open(hostsFile)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		ip := fields[0]
		for _, h := range fields[1:] {
			if h == host {
				return ip
			}
		}
	}

	if err := scanner.Err(); err != nil {
		GB403Logger.Error().
			Metadata("resolveFromHostsFile()", "failed").
			Msgf("Error reading hosts file: %v", err)
		return ""
	}

	return ""
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
			GB403Logger.Error().Msgf("%v", err)
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
		GB403Logger.Verbose().Msgf("Handling IPv6: %s", ip)
	} else {
		GB403Logger.Verbose().Msgf("Handling IPv4: %s", ip)
	}

	// Check both ports and store all available schemes
	for _, port := range []string{"80", "443"} {
		GB403Logger.Verbose().Msgf("Probing %s:%s", ip, port)
		if scheme := s.probeScheme(ip, port); scheme != "" {
			GB403Logger.Verbose().Msgf("Found open port %s:%s -> %s", ip, port, scheme)
			if services[scheme] == nil {
				services[scheme] = make(map[string][]string)
			}
			services[scheme][ip] = append(services[scheme][ip], port)
		}
	}

	GB403Logger.Verbose().Msgf("Caching result for %s: IPv4=%v, IPv6=%v",
		ip, result.IPv4Services, result.IPv6Services)
	s.cache.Set(ip, result)
}

func (s *ReconService) handleDomain(host string) {
	ips, err := s.resolveHost(host)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to resolve host %s: %v", host, err)
		return
	}

	result := &ReconResult{
		Hostname:     host,
		IPv4Services: make(map[string]map[string][]string),
		IPv6Services: make(map[string]map[string][]string),
		CNAMEs:       ips.CNAMEs,
	}

	// Store IPs for later use but probe the domain
	// Try both HTTP and HTTPS regardless of original scheme
	if scheme := s.probeScheme(host, "443"); scheme != "" {
		// Store all resolved IPs under this scheme
		for _, ip := range ips.IPv4 {
			if result.IPv4Services[scheme] == nil {
				result.IPv4Services[scheme] = make(map[string][]string)
			}
			result.IPv4Services[scheme][ip] = append(result.IPv4Services[scheme][ip], "443")
		}
		for _, ip := range ips.IPv6 {
			if result.IPv6Services[scheme] == nil {
				result.IPv6Services[scheme] = make(map[string][]string)
			}
			result.IPv6Services[scheme][ip] = append(result.IPv6Services[scheme][ip], "443")
		}
	}

	if scheme := s.probeScheme(host, "80"); scheme != "" {
		// Store all resolved IPs under this scheme
		for _, ip := range ips.IPv4 {
			if result.IPv4Services[scheme] == nil {
				result.IPv4Services[scheme] = make(map[string][]string)
			}
			result.IPv4Services[scheme][ip] = append(result.IPv4Services[scheme][ip], "80")
		}
		for _, ip := range ips.IPv6 {
			if result.IPv6Services[scheme] == nil {
				result.IPv6Services[scheme] = make(map[string][]string)
			}
			result.IPv6Services[scheme][ip] = append(result.IPv6Services[scheme][ip], "80")
		}
	}

	s.cache.Set(host, result)
}

func (s *ReconService) resolveHost(hostname string) (*IPAddrs, error) {
	result := &IPAddrs{}

	// Special handling for localhost and hosts file entries
	if ip := resolveFromHostsFile(hostname); ip != "" {
		GB403Logger.Verbose().
			Msgf("Resolved %s locally to %s", hostname, ip)

		// Determine if IPv4 or IPv6
		if strings.Contains(ip, ":") {
			result.IPv6 = append(result.IPv6, ip)
		} else {
			result.IPv4 = append(result.IPv4, ip)
		}
		return result, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

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

func (s *ReconService) probeScheme(host, port string) string {
	addr := net.JoinHostPort(host, port)
	GB403Logger.Verbose().Msgf("Probing %s", addr)

	client := &fasthttp.Client{
		NoDefaultUserAgentHeader:      true,
		DisableHeaderNamesNormalizing: true,
		DisablePathNormalizing:        true,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		},
	}

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	switch port {
	case "443":
		req.SetRequestURI(fmt.Sprintf("https://%s", addr))
		err := client.Do(req, resp)
		if err != nil {
			GB403Logger.Verbose().Msgf("HTTPS error on %s: %v", addr, err)
			return ""
		}
		return "https"

	case "80":
		req.SetRequestURI(fmt.Sprintf("http://%s", addr))
		err := client.Do(req, resp)
		if err != nil {
			GB403Logger.Verbose().Msgf("HTTP error on %s: %v", addr, err)
			return ""
		}
		return "http"
	}

	return ""
}

func (s *ReconService) GetCache() *ReconCache {
	return s.cache
}
