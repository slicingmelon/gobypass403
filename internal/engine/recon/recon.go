package recon

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp/dialer"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/slicingmelon/go-rawurlparser"
	"github.com/valyala/fasthttp"
)

type ReconService struct {
	dialer       *fasthttp.TCPDialer
	cache        *ReconCache
	dnsServers   []string
	dohProviders []string
}

type ReconResult struct {
	Hostname     string
	IPv4Services map[string]map[string][]string // scheme -> ipv4 -> []ports
	IPv6Services map[string]map[string][]string // scheme -> ipv6 -> []ports
	CNAMEs       []string
}

func NewReconService() *ReconService {
	dnsServers := []string{
		"8.8.8.8:53",                // Google
		"1.1.1.1:53",                // Cloudflare
		"9.9.9.9:53",                // Quad9
		"208.67.222.222:53",         // OpenDNS
		"8.8.4.4:53",                // Google Secondary
		"1.0.0.1:53",                // Cloudflare Secondary
		"149.112.112.112:53",        // Quad9 Secondary
		"208.67.220.220:53",         // OpenDNS Secondary
		"[2001:4860:4860::8888]:53", // Google IPv6
		"[2606:4700:4700::1111]:53", // Cloudflare IPv6
		"[2620:fe::fe]:53",          // Quad9 IPv6
	}

	// Add DoH providers that support IPv6
	dohProviders := []string{
		"https://cloudflare-dns.com/dns-query",
		"https://dns.google/dns-query",
		"https://dns.quad9.net/dns-query",
	}

	return &ReconService{
		dialer:       dialer.GetSharedDialer(),
		cache:        NewReconCache(),
		dnsServers:   dnsServers,
		dohProviders: dohProviders,
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

	result := &ReconResult{
		Hostname:     host,
		IPv4Services: make(map[string]map[string][]string),
		IPv6Services: make(map[string]map[string][]string),
	}

	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		ips, err = r.ResolveDomain(host)
		if err != nil {
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

	// Single probing pass
	for _, ip := range ips {
		ipStr := ip.String()
		services := result.IPv4Services
		if ip.To4() == nil {
			services = result.IPv6Services
		}

		for _, port := range ports {
			protocol, ok := r.ProbePort(ipStr, port)
			if !ok {
				continue
			}

			// Print successful probe
			GB403Logger.Verbose().Msgf("%s://%s:%s [%s]", protocol, host, port, ipStr)

			if services[protocol] == nil {
				services[protocol] = make(map[string][]string)
			}
			services[protocol][ipStr] = append(services[protocol][ipStr], port)
		}
	}

	// Cache result
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

func (r *ReconService) ProbePort(ip string, port string) (string, bool) {
	addr := net.JoinHostPort(ip, port)

	// Try HTTPS first
	conn, err := r.dialer.DialDualStackTimeout(addr, 3*time.Second)
	if err == nil {
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         ip,
		})
		tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
		if tlsConn.Handshake() == nil {
			tlsConn.Close()
			return "https", true
		}
		conn.Close()
	}

	// Try HTTP
	conn2, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return "", false
	}
	defer conn2.Close()

	_, err = fmt.Fprintf(conn2, "HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n", addr)
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

func (r *ReconService) ResolveDomain(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Expected responses from:
	// - the system resolver (1)
	// - each custom DNS server (len(r.dnsServers))
	// - one DoH query covering both A and AAAA (1)
	expectedResponses := len(r.dnsServers) + 2

	resultChan := make(chan []net.IP, expectedResponses)
	errChan := make(chan error, expectedResponses)
	doneChan := make(chan struct{})

	var ips []net.IP
	seen := make(map[string]struct{})
	responses := 0

	dohTimeout := 2 * time.Second

	// Collector goroutine which aggregates unique IPs.
	go func() {
		for {
			select {
			case resolvedIPs := <-resultChan:
				responses++
				for _, ip := range resolvedIPs {
					key := ip.String()
					if _, exists := seen[key]; !exists {
						seen[key] = struct{}{}
						ips = append(ips, ip)
					}
				}
			case <-errChan:
				responses++
			case <-ctx.Done():
				doneChan <- struct{}{}
				return
			}

			if len(ips) > 0 || responses >= expectedResponses {
				doneChan <- struct{}{}
				return
			}
		}
	}()

	// 1. Launch system resolver query with explicit IPv4 and IPv6.
	go func() {
		var systemIPs []net.IP
		if ips4, err := net.DefaultResolver.LookupIP(ctx, "ip4", host); err == nil {
			systemIPs = append(systemIPs, ips4...)
		}
		if ips6, err := net.DefaultResolver.LookupIP(ctx, "ip6", host); err == nil {
			systemIPs = append(systemIPs, ips6...)
		}
		if len(systemIPs) > 0 {
			resultChan <- systemIPs
		} else {
			errChan <- fmt.Errorf("system resolver returned no IPs")
		}
	}()

	// 2. Launch queries for each configured DNS server.
	for _, server := range r.dnsServers {
		go func(server string) {
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: 2 * time.Second}
					return d.DialContext(ctx, "udp", server)
				},
			}
			var dnsIPs []net.IP
			if ips4, err := resolver.LookupIP(ctx, "ip4", host); err == nil {
				dnsIPs = append(dnsIPs, ips4...)
			}
			if ips6, err := resolver.LookupIP(ctx, "ip6", host); err == nil {
				dnsIPs = append(dnsIPs, ips6...)
			}
			if len(dnsIPs) > 0 {
				resultChan <- dnsIPs
			} else {
				errChan <- fmt.Errorf("DNS server %s returned no IPs", server)
			}
		}(server)
	}

	// 3. DoH resolution using Cloudflare DNS.
	// First perform a query for A records, then for AAAA records, and merge the results.
	go func() {
		var allIPs []net.IP
		client := &fasthttp.Client{
			TLSConfig:   &tls.Config{InsecureSkipVerify: true},
			ReadTimeout: dohTimeout,
			Dial:        r.dialer.Dial,
		}

		// Query A records.
		reqA := fasthttp.AcquireRequest()
		respA := fasthttp.AcquireResponse()
		reqA.SetRequestURI(fmt.Sprintf("https://cloudflare-dns.com/dns-query?name=%s&type=A", host))
		reqA.Header.Set("Accept", "application/dns-json")
		if err := client.DoTimeout(reqA, respA, 5*time.Second); err == nil {
			var dohResponse struct {
				Answer []struct {
					Type int    `json:"type"`
					Data string `json:"data"`
				} `json:"Answer"`
			}
			if json.Unmarshal(respA.Body(), &dohResponse) == nil {
				for _, answer := range dohResponse.Answer {
					// Type 1 indicates an A record.
					if answer.Type == 1 {
						if ip := net.ParseIP(answer.Data); ip != nil {
							allIPs = append(allIPs, ip)
						}
					}
				}
			}
		}
		fasthttp.ReleaseRequest(reqA)
		fasthttp.ReleaseResponse(respA)

		// Query AAAA records.
		reqAAAA := fasthttp.AcquireRequest()
		respAAAA := fasthttp.AcquireResponse()
		reqAAAA.SetRequestURI(fmt.Sprintf("https://cloudflare-dns.com/dns-query?name=%s&type=AAAA", host))
		reqAAAA.Header.Set("Accept", "application/dns-json")
		if err := client.DoTimeout(reqAAAA, respAAAA, 5*time.Second); err == nil {
			var dohResponse struct {
				Answer []struct {
					Type int    `json:"type"`
					Data string `json:"data"`
				} `json:"Answer"`
			}
			if json.Unmarshal(respAAAA.Body(), &dohResponse) == nil {
				for _, answer := range dohResponse.Answer {
					// Type 28 indicates an AAAA record.
					if answer.Type == 28 {
						if ip := net.ParseIP(answer.Data); ip != nil {
							allIPs = append(allIPs, ip)
						}
					}
				}
			}
		}
		fasthttp.ReleaseRequest(reqAAAA)
		fasthttp.ReleaseResponse(respAAAA)

		if len(allIPs) > 0 {
			resultChan <- allIPs
		} else {
			errChan <- fmt.Errorf("DoH query failed for both A and AAAA records")
		}
	}()

	// Wait until either done or timeout.
	select {
	case <-doneChan:
		if len(ips) > 0 {
			return ips, nil
		}
		return nil, fmt.Errorf("all DNS resolution attempts failed")
	case <-ctx.Done():
		return nil, fmt.Errorf("DNS resolution timeout")
	}
}

func convertIPAddrs(ipAddrs []net.IPAddr) []net.IP {
	ips := make([]net.IP, len(ipAddrs))
	for i, addr := range ipAddrs {
		ips[i] = addr.IP
	}
	return ips
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
