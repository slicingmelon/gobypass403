/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package recon

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
	"github.com/valyala/fasthttp"
)

/*
ReconService is a service that performs reconnaissance on a host.
The recon is meant to probe the hosts that are going to be tested for WAF bypasses.

Agenda:

# 1. Service Initialization:

	func NewReconService() *ReconService {
		// Gets shared fasthttp dialer that includes:
		//   - Custom resolver with parallel DNS resolution strategy
		//   - DNS caching (120 minutes duration)
		//   - Concurrency settings (2048)
		// Creates a new cache instance for recon results

# 2. Main Processing Flow (ProcessHost function):
func (r *ReconService) ProcessHost(input string) (*ReconResult, error) {
1. Extract host and port from input
2. Check recon cache first for existing results
3. Create new result structure
4. Handle IP resolution:
  - If input is IP, use directly
  - Otherwise, resolve domain via ResolveDomain()

5. Log successful DNS resolution
6. Probe ports (80, 443, custom if specified)
7. For each IP:
  - Test each port
  - Determine protocol (http/https)
  - Store results in IPv4/IPv6 services maps

8. Cache results
9. Return results

# 3. DNS Resolution (ResolveDomain function):
Uses fasthttp's dialer with CustomResolver that implements parallel resolution:
1. System resolver (IPv4 + IPv6)
2. Custom DNS servers:
  - Multiple providers (Cloudflare, Google, Quad9, OpenDNS)
  - Both IPv4 and IPv6 servers

3. DoH (DNS over HTTPS):
  - Multiple providers (Cloudflare, Google, Quad9)
  - Automatic fastest provider selection
  - Built-in caching
  - Both A and AAAA records

All resolution methods run in parallel with a 5-second total timeout.
First valid response can return early.
Results are automatically cached by fasthttp's dialer.

# 4. Port Probing (ProbePort method):
For each IP+port combination:
1. Try HTTPS first using fasthttp's dialer:
  - 3-second connection timeout
  - 2-second TLS handshake timeout
  - Insecure skip verify enabled

2. Fallback to HTTP if HTTPS fails:
  - 3-second connection timeout
  - Simple HEAD request
  - 3-second read timeout

Returns protocol ("http"/"https") and success status

Note: All DNS operations utilize fasthttp's built-in caching mechanism,
which maintains resolved addresses for 120 minutes and implements
round-robin selection for multiple IPs.
*/
type ReconService struct {
	dialer     *fasthttp.TCPDialer
	dnsServers []string
	cache      *ReconCache
}

type ReconResult struct {
	Hostname     string
	IPv4Services map[string]map[string][]string // scheme -> ipv4 -> []ports
	IPv6Services map[string]map[string][]string // scheme -> ipv6 -> []ports
	CNAMEs       []string
}

func NewReconService() *ReconService {
	// Get the shared dialer that already has our custom resolver
	dialer := GetSharedDialer()

	return &ReconService{
		dialer: dialer,
		dnsServers: []string{
			"1.1.1.1:53",                // Cloudflare
			"9.9.9.9:53",                // Quad9
			"208.67.222.222:53",         // OpenDNS
			"[2606:4700:4700::1111]:53", // Cloudflare IPv6
			"[2620:fe::fe]:53",          // Quad9 IPv6
		},
		cache: NewReconCache(),
	}
}

// ProcessHost handles both domains and IPs
func (r *ReconService) ProcessHost(input string) (*ReconResult, error) {
	// Extract host and port
	host, customPort, err := extractHostAndPort(input)
	if err != nil {
		return nil, err
	}

	// Check cache first
	if cached, err := r.cache.Get(host); err == nil && cached != nil {
		return cached, nil
	}

	// Update this initialization to include CNAMEs slice
	result := &ReconResult{
		Hostname:     host,
		IPv4Services: make(map[string]map[string][]string),
		IPv6Services: make(map[string]map[string][]string),
		CNAMEs:       make([]string, 0), // Initialize the slice
	}

	// IP and CNAME resolution happens in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex // To protect concurrent access to result

	// Only do CNAME lookup if it's not an IP address
	if net.ParseIP(host) == nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cname, err := r.ResolveCNAME(host)
			if err == nil && cname != "" && cname != host {
				mu.Lock()
				result.CNAMEs = append(result.CNAMEs, cname)
				mu.Unlock()
				GB403Logger.Verbose().Msgf("Resolved CNAME for %s: %s", host, cname)
			}
		}()
	}

	// Continue with existing IP resolution code...
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		ips, err = r.ResolveDomain(host)
		if err != nil {
			wg.Wait() // Wait for CNAME resolution to finish before returning error
			return nil, fmt.Errorf("DNS resolution failed: %v", err)
		}
	}

	// Print successful DNS resolution
	ipStrings := make([]string, 0, len(ips))
	for _, ip := range ips {
		ipStrings = append(ipStrings, ip.String())
	}
	GB403Logger.Verbose().Msgf("Resolved %s -> [%s]", host, strings.Join(ipStrings, ", "))

	// Ports to probe
	ports := []string{"80", "443"}
	if customPort != "" && !slices.Contains(ports, customPort) {
		ports = append(ports, customPort)
	}

	// Create a wait group for parallel port probing
	for _, ip := range ips {
		ipStr := ip.String()
		services := result.IPv4Services
		if ip.To4() == nil {
			services = result.IPv6Services
		}

		for _, port := range ports {
			wg.Add(1)
			go func(ip string, port string, services map[string]map[string][]string) {
				defer wg.Done()
				protocol, ok := r.ProbePort(ip, port, host)
				if !ok {
					return
				}

				// Print successful probe
				GB403Logger.Verbose().Msgf("%s://%s:%s [%s]", protocol, host, port, ip)

				mu.Lock()
				if services[protocol] == nil {
					services[protocol] = make(map[string][]string)
				}
				services[protocol][ip] = append(services[protocol][ip], port)
				mu.Unlock()
			}(ipStr, port, services)
		}
	}

	// Wait for all goroutines to complete (both CNAME and port probing)
	wg.Wait()

	// Cache result (now with CNAMEs)
	if err := r.cache.Set(host, result); err != nil {
		GB403Logger.Error().Msgf("Failed to cache result: %v\n", err)
	}

	return result, nil
}

func (r *ReconService) Run(urls []string) error {
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
				result, err := r.ProcessHost(host)
				if err != nil {
					select {
					case results <- fmt.Errorf("host %s: %v", host, err):
					default:
					}
					continue
				}

				// Cache the result after successful processing
				if err := r.cache.Set(host, result); err != nil {
					GB403Logger.Error().Msgf("Failed to cache %s: %v\n", host, err)
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
			GB403Logger.Error().Msgf("%v\n", err)
		}
	}

	return nil
}

// ProbePort probes a port on an IP address and returns the protocol (http or https)
func (r *ReconService) ProbePort(ip string, port string, host string) (string, bool) {
	addr := net.JoinHostPort(ip, port)

	// For IP probing, we create a specialized dialer without DNS resolution
	ipProbeDialer := &fasthttp.TCPDialer{
		Concurrency:          1024,
		DNSCacheDuration:     10 * time.Minute,
		DisableDNSResolution: true,
	}

	// Try HTTPS first
	conn, err := ipProbeDialer.Dial(addr)
	if err != nil {
		GB403Logger.Verbose().Msgf("TLS dial error for %s: %v", addr, err)
	} else {
		defer conn.Close()
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			ServerName:         host,
		}

		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.SetDeadline(time.Now().Add(3 * time.Second)); err == nil {
			if err := tlsConn.Handshake(); err == nil {
				tlsConn.Close()
				return "https", true
			} else {
				GB403Logger.Verbose().Msgf("TLS handshake error for %s: %v", addr, err)
			}
		} else {
			GB403Logger.Verbose().Msgf("TLS deadline error for %s: %v", addr, err)
		}
	}

	// Try HTTP
	conn2, err := ipProbeDialer.Dial(addr)
	if err != nil {
		return "", false
	}
	defer conn2.Close()

	_, err = fmt.Fprintf(conn2, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", host)
	if err != nil {
		return "", false // Port is open but not HTTP/HTTPS
	}

	buf := make([]byte, 1024)
	conn2.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn2.Read(buf)
	if err != nil {
		return "", false
	}

	if n > 0 && strings.HasPrefix(string(buf), "HTTP") {
		return "http", true
	}

	return "", false // Not HTTP/HTTPS
}

// ResolveDomain resolves a domain name to an array of IP addresses
// This uses the dialer's custom resolver that implements parallel DNS resolution strategy
func (r *ReconService) ResolveDomain(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Log that we're resolving the domain
	GB403Logger.Verbose().Msgf("Resolving domain %s using custom parallel resolver", host)

	// Use the dialer's custom LookupIPAddr function which implements our parallel strategy
	// This will try system resolver, DoH, and multiple DNS servers concurrently
	ipAddrs, err := r.dialer.Resolver.LookupIPAddr(ctx, host)
	if err != nil {
		GB403Logger.Debug().Msgf("Failed to resolve domain %s: %v", host, err)
		return nil, fmt.Errorf("DNS resolution failed for %s: %v", host, err)
	}

	if len(ipAddrs) == 0 {
		GB403Logger.Debug().Msgf("No IP addresses found for domain %s", host)
		return nil, fmt.Errorf("no IP addresses found for domain %s", host)
	}

	// Convert IPAddr to IP
	ips := make([]net.IP, len(ipAddrs))
	for i, addr := range ipAddrs {
		ips[i] = addr.IP
	}

	return ips, nil
}

func (r *ReconService) ResolveCNAME(host string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// If the resolver in dialer is our CustomResolver, use it
	if customResolver, ok := r.dialer.Resolver.(*CustomResolver); ok {
		return customResolver.LookupCNAME(ctx, host)
	}

	// Fallback to standard resolver
	return net.DefaultResolver.LookupCNAME(ctx, host)
}

func extractHostAndPort(input string) (host string, port string, err error) {
	input = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(input, "http://"), "https://"))
	if input == "" {
		return "", "", fmt.Errorf("empty hostname")
	}

	// Split host and port if exists
	host, port, err = net.SplitHostPort(input)
	if err != nil {
		// No port specified, just return the host
		return input, "", nil
	}
	return host, port, nil
}
