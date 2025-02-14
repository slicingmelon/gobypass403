package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/phuslu/fastdns"
	"github.com/slicingmelon/go-bypass-403/internal/engine/recon"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

type FastDialer struct {
	dnsClient  *fastdns.Client
	dohClient  *fastdns.Client
	cache      *recon.ReconCache
	dnsServers []string
}

func NewFastDialer() *FastDialer {
	// Setup standard DNS client
	standardClient := &fastdns.Client{
		Timeout: 3 * time.Second,
		Addr:    "8.8.8.8:53", // Start with Google DNS
	}

	// Setup DoH client
	dohEndpoint, _ := url.Parse("https://1.1.1.1/dns-query")
	dohClient := &fastdns.Client{
		Addr: dohEndpoint.String(),
		Dialer: &fastdns.HTTPDialer{
			Endpoint: dohEndpoint,
			Header: http.Header{
				"content-type": {"application/dns-message"},
				"user-agent":   {"fastdns/1.0"},
			},
			Transport: &http.Transport{
				MaxIdleConns:        100,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}

	return &FastDialer{
		dnsClient: standardClient,
		dohClient: dohClient,
		cache:     recon.NewReconCache(),
		dnsServers: []string{
			"8.8.8.8:53",        // Google
			"1.1.1.1:53",        // Cloudflare
			"9.9.9.9:53",        // Quad9
			"208.67.222.222:53", // OpenDNS
		},
	}
}

func (f *FastDialer) ResolveDomain(host string) ([]net.IP, error) {
	// Special case handling for localhost
	if host == "localhost" {
		return []net.IP{
			net.ParseIP("127.0.0.1"), // IPv4 loopback
			net.ParseIP("::1"),       // IPv6 loopback
		}, nil
	}

	type result struct {
		ips []net.IP
		err error
		src string
	}

	resultChan := make(chan result, len(f.dnsServers)+1) // +1 for DoH
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Launch UDP DNS queries
	for _, dnsServer := range f.dnsServers {
		go func(server string) {
			client := &fastdns.Client{
				Timeout: 3 * time.Second,
				Addr:    server,
			}

			GB403Logger.Debug().Msgf("Trying DNS server %s for %s", server, host)
			ips, err := client.LookupNetIP(ctx, "ip", host)

			if err != nil {
				GB403Logger.Debug().Msgf("DNS lookup failed with %s: %v", server, err)
				resultChan <- result{nil, err, server}
				return
			}

			var resolvedIPs []net.IP
			for _, ip := range ips {
				resolvedIPs = append(resolvedIPs, ip.AsSlice())
			}
			resultChan <- result{resolvedIPs, nil, server}
		}(dnsServer)
	}

	// Launch DoH query
	go func() {
		ips, err := f.dohClient.LookupNetIP(ctx, "ip", host)
		if err != nil {
			GB403Logger.Debug().Msgf("DoH lookup failed: %v", err)
			resultChan <- result{nil, err, "DoH"}
			return
		}

		var resolvedIPs []net.IP
		for _, ip := range ips {
			resolvedIPs = append(resolvedIPs, ip.AsSlice())
		}
		resultChan <- result{resolvedIPs, nil, "DoH"}
	}()

	// Collect results
	var lastErr error
	for i := 0; i < len(f.dnsServers)+1; i++ {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("resolution timeout after %v", 5*time.Second)
		case r := <-resultChan:
			if r.err == nil && len(r.ips) > 0 {
				GB403Logger.Debug().Msgf("Successful resolution from %s", r.src)
				return r.ips, nil
			}
			lastErr = r.err
		}
	}

	return nil, fmt.Errorf("all DNS resolvers failed, last error: %v", lastErr)
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
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return "", false
	}
	defer conn.Close()

	// Try TLS handshake first
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
	if tlsConn.Handshake() == nil {
		return "https", true
	}

	// If TLS fails, try HTTP
	conn2, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return "", false
	}
	defer conn2.Close()

	_, err = fmt.Fprintf(conn2, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", addr)
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

	return "tcp", true // Port is open but protocol unknown
}

// ProcessHost handles both domains and IPs
func (f *FastDialer) ProcessHost(input string) (*recon.ReconResult, error) {
	// Extract host and port
	host, customPort, err := extractHostAndPort(input)
	if err != nil {
		return nil, err
	}

	// Check cache
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
	if customPort != "" && !contains(ports, customPort) {
		ports = append(ports, customPort)
	}

	// Probe services for each IP
	for _, ip := range ips {
		ipStr := ip.String()
		services := result.IPv4Services
		if ip.To4() == nil {
			services = result.IPv6Services
		}

		for _, port := range ports {
			if protocol, ok := f.ProbePort(ipStr, port); ok {
				if services[protocol] == nil {
					services[protocol] = make(map[string][]string)
				}
				services[protocol][ipStr] = append(services[protocol][ipStr], port)
			}
		}
	}

	// Cache result
	if err := f.cache.Set(host, result); err != nil {
		GB403Logger.Error().Msgf("Failed to cache result: %v", err)
	}

	return result, nil
}

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
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
