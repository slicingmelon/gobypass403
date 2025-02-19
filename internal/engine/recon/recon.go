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

	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/slicingmelon/go-rawurlparser"
	"github.com/valyala/fasthttp"
)

var (
	instance *ReconService
	once     sync.Once
)

// GetInstance returns the singleton instance of ReconService
func GetReconInstance() *ReconService {
	once.Do(func() {
		instance = NewReconService()
	})
	return instance
}

type ReconService struct {
	cache      *ReconCache
	dialer     *fasthttp.TCPDialer
	resolver   *net.Resolver
	dnsServers []string
	dialerOnce sync.Once
}

var dnsServers = []string{
	"8.8.8.8:53",        // Google
	"1.1.1.1:53",        // Cloudflare
	"9.9.9.9:53",        // Quad9
	"208.67.222.222:53", // OpenDNS
}

// GetDialer returns the initialized TCPDialer with proper timeout
func (r *ReconService) GetDialer() *fasthttp.TCPDialer {
	r.dialerOnce.Do(func() {
		r.dialer = &fasthttp.TCPDialer{
			Concurrency:      2000,
			DNSCacheDuration: 60 * time.Minute,
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					// Extract hostname from address
					host, _, err := net.SplitHostPort(address)
					if err != nil {
						host = address
					}

					// Try to resolve using our robust ResolveDomain method
					ips, err := r.ResolveDomain(host)
					if err == nil && len(ips) > 0 {
						// Use the first resolved IP
						d := net.Dialer{Timeout: 2 * time.Second}
						return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), "53"))
					}

					// Fallback to default DNS server if everything fails
					d := net.Dialer{Timeout: 2 * time.Second}
					return d.DialContext(ctx, "udp", r.dnsServers[0])
				},
			},
		}
	})
	return r.dialer
}

type ReconResult struct {
	Hostname     string
	IPv4Services map[string]map[string][]string // scheme -> ipv4 -> []ports
	IPv6Services map[string]map[string][]string // scheme -> ipv6 -> []ports
	CNAMEs       []string
}

func NewReconService() *ReconService {
	return &ReconService{
		cache:      NewReconCache(),
		dnsServers: dnsServers,
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

func (r *ReconService) ResolveDomain(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create channels for all resolution methods
	resultChan := make(chan []net.IP, len(r.dnsServers)+2)
	errChan := make(chan error, len(r.dnsServers)+2)
	doneChan := make(chan struct{})

	// Track results
	var ips []net.IP
	seen := make(map[string]struct{})
	responses := 0
	expectedResponses := len(r.dnsServers) + 2 // DNS servers + system resolver + DoH

	// Start result collector goroutine
	go func() {
		for {
			select {
			case resolvedIPs := <-resultChan:
				responses++
				// Add any new IPs to our result set
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

			// Signal completion if we have IPs or all resolvers responded
			if len(ips) > 0 || responses >= expectedResponses {
				doneChan <- struct{}{}
				return
			}
		}
	}()

	// 1. Launch system resolver
	go func() {
		if ips, err := net.DefaultResolver.LookupIPAddr(ctx, host); err == nil {
			resultChan <- convertIPAddrs(ips)
		} else {
			errChan <- err
		}
	}()

	// 2. Launch all DNS servers
	for _, server := range r.dnsServers {
		go func(server string) {
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: 2 * time.Second}
					return d.DialContext(ctx, "udp", server)
				},
			}

			if ips, err := resolver.LookupIPAddr(ctx, host); err == nil {
				resultChan <- convertIPAddrs(ips)
			} else {
				errChan <- err
			}
		}(server)
	}

	// 3. Launch DoH resolver
	go func() {
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		defer func() {
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
		}()

		req.SetRequestURI(fmt.Sprintf("https://cloudflare-dns.com/dns-query?name=%s&type=A,AAAA", host))
		req.Header.Set("Accept", "application/dns-json")

		client := &fasthttp.Client{
			TLSConfig:   &tls.Config{InsecureSkipVerify: true},
			ReadTimeout: 5 * time.Second,
			Dial:        r.dialer.Dial,
		}

		if err := client.DoTimeout(req, resp, 5*time.Second); err == nil {
			var dohResponse struct {
				Answer []struct {
					Type int    `json:"type"`
					Data string `json:"data"`
				} `json:"Answer"`
			}

			if json.Unmarshal(resp.Body(), &dohResponse) == nil {
				var ips []net.IP
				for _, answer := range dohResponse.Answer {
					if ip := net.ParseIP(answer.Data); ip != nil && (answer.Type == 1 || answer.Type == 28) {
						ips = append(ips, ip)
					}
				}
				resultChan <- ips
			} else {
				errChan <- fmt.Errorf("DoH JSON unmarshal failed")
			}
		} else {
			errChan <- err
		}
	}()

	// Wait for completion or timeout
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

// ProbePort checks if a specific port is open and what protocol it speaks
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
