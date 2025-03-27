package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/slicingmelon/gobypass403/core/engine/recon"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
	"github.com/valyala/fasthttp"
)

type FastDialer struct {
	resolver   *net.Resolver
	cache      *recon.ReconCache
	httpClient *fasthttp.HostClient
	dialer     *fasthttp.TCPDialer
	dnsServers []string
}

func NewFastDialer() *FastDialer {
	dnsServers := []string{
		"8.8.8.8:53",        // Google
		"1.1.1.1:53",        // Cloudflare
		"9.9.9.9:53",        // Quad9
		"208.67.222.222:53", // OpenDNS
	}

	dialer := &fasthttp.TCPDialer{
		Concurrency:      500,
		DNSCacheDuration: 10 * time.Minute,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 2 * time.Second}
				return d.DialContext(ctx, "udp", dnsServers[0]) // First server as primary
			},
		},
	}

	return &FastDialer{
		dialer:     dialer,
		cache:      recon.NewReconCache(),
		dnsServers: dnsServers,
		httpClient: &fasthttp.HostClient{
			Dial: func(addr string) (net.Conn, error) {
				return dialer.DialDualStackTimeout(addr, 5*time.Second)
			},
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			ReadTimeout:         5 * time.Second,
			WriteTimeout:        5 * time.Second,
			MaxIdleConnDuration: 30 * time.Second,
		},
	}
}

func (f *FastDialer) ResolveDomain(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try system resolver first
	if ips, err := net.DefaultResolver.LookupIPAddr(ctx, host); err == nil {
		return convertIPAddrs(ips), nil
	}

	// Try configured DNS servers
	resultChan := make(chan []net.IP, len(f.dnsServers))
	for _, server := range f.dnsServers {
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
			}
		}(server)
	}

	// Try DoH as final fallback
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
			Dial:        f.dialer.Dial,
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
			}
		}
	}()

	// Collect results with priority
	var ips []net.IP
	seen := make(map[string]struct{})

	for i := 0; i < len(f.dnsServers)+1; i++ {
		select {
		case <-ctx.Done():
			if len(ips) > 0 {
				return ips, nil
			}
			return nil, fmt.Errorf("DNS resolution timeout")
		case resolvedIPs := <-resultChan:
			for _, ip := range resolvedIPs {
				key := ip.String()
				if _, exists := seen[key]; !exists {
					seen[key] = struct{}{}
					ips = append(ips, ip)
				}
			}
		}
	}

	if len(ips) > 0 {
		return ips, nil
	}
	return nil, fmt.Errorf("all DNS resolution attempts failed")
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

// ProbePort checks if a specific port is open and what protocol it speaks
func (f *FastDialer) ProbePort(ip string, port string) (string, bool) {
	addr := net.JoinHostPort(ip, port)

	// First attempt HTTPS
	conn, err := f.dialer.DialDualStackTimeout(addr, 2*time.Second)
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

	// Then check HTTP
	conn2, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return "", false
	}
	defer conn2.Close()

	_, err = fmt.Fprintf(conn2, "HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n", addr)
	if err != nil {
		return "tcp", true // At least the port is open
	}

	buf := make([]byte, 1024)
	conn2.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn2.Read(buf)
	if err != nil {
		return "tcp", true
	}

	if n > 0 && strings.HasPrefix(string(buf), "HTTP") {
		return "http", true
	}

	return "tcp", true
}

// ProcessHost handles both domains and IPs
func (f *FastDialer) ProcessHost(input string) (*recon.ReconResult, error) {
	// Extract host and port
	host, customPort, err := extractHostAndPort(input)
	if err != nil {
		return nil, err
	}

	// Check cache first
	if cached, err := f.cache.Get(host); err == nil && cached != nil {
		return cached, nil
	}

	result := &recon.ReconResult{
		Hostname:     host,
		IPv4Services: make(map[string]map[string][]string),
		IPv6Services: make(map[string]map[string][]string),
	}

	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		ips, err = f.ResolveDomain(host)
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed: %v", err)
		}
	}

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
			protocol, ok := f.ProbePort(ipStr, port)
			if !ok {
				continue
			}

			if services[protocol] == nil {
				services[protocol] = make(map[string][]string)
			}
			services[protocol][ipStr] = append(services[protocol][ipStr], port)
		}
	}

	// Cache result with fasthttp-optimized validation
	if err := f.cache.Set(host, result); err != nil {
		GB403Logger.Error().Msgf("Failed to cache result: %v", err)
	}

	return result, nil
}

func main() {
	var (
		hostsFile string
		hostList  string
	)

	flag.StringVar(&hostsFile, "f", "", "File containing hosts (one per line)")
	flag.StringVar(&hostList, "hosts", "", "Comma-separated list of hosts")
	flag.Parse()

	// Get hosts
	var hosts []string
	switch {
	case hostsFile != "":
		if data, err := os.ReadFile(hostsFile); err == nil {
			hosts = strings.Split(strings.TrimSpace(string(data)), "\n")
		}
	case hostList != "":
		hosts = strings.Split(hostList, ",")
	default:
		fmt.Println("Please provide hosts using either -f or -hosts flag")
		flag.Usage()
		os.Exit(1)
	}

	dialer := NewFastDialer()

	// Process hosts and print results immediately
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}

		fmt.Printf("\nScanning %s...\n", host)
		result, err := dialer.ProcessHost(host)
		if err != nil {
			GB403Logger.Error().Msgf("Error processing %s: %v", host, err)
			continue
		}

		// Print results immediately after scanning
		if result != nil {
			printResult(result)
		}
	}
}

func printResult(result *recon.ReconResult) {
	if result == nil {
		return
	}

	fmt.Printf("\nResults for %s:\n", result.Hostname)

	if len(result.CNAMEs) > 0 {
		fmt.Printf("CNAMEs: %v\n", result.CNAMEs)
	}

	if len(result.IPv4Services) > 0 {
		fmt.Println("IPv4 Services:")
		for scheme, ipMap := range result.IPv4Services {
			for ip, ports := range ipMap {
				fmt.Printf("  %s: %s on ports %v\n", scheme, ip, ports)
			}
		}
	}

	if len(result.IPv6Services) > 0 {
		fmt.Println("IPv6 Services:")
		for scheme, ipMap := range result.IPv6Services {
			for ip, ports := range ipMap {
				fmt.Printf("  %s: %s on ports %v\n", scheme, ip, ports)
			}
		}
	}
}
