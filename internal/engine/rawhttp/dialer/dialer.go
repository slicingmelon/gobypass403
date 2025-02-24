package dialer

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/likexian/doh"
	"github.com/likexian/doh/dns"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
)

var (
	sharedDialer *fasthttp.TCPDialer
	onceDialer   sync.Once
)

type CustomResolver struct {
	dohClient  *doh.DoH
	dnsServers []string
}

func NewCustomResolver(dnsServers []string) *CustomResolver {
	// Initialize DoH client with multiple providers for automatic fastest selection
	dohClient := doh.Use(
		doh.CloudflareProvider,
		doh.GoogleProvider,
		doh.Quad9Provider,
	)

	// Enable caching for better performance
	dohClient.EnableCache(true)

	return &CustomResolver{
		dohClient:  dohClient,
		dnsServers: dnsServers,
	}
}

// LookupIPAddr resolves a host and returns an array of IP addresses
// This is the custom resolver that implements parallel DNS resolution strategy
func (r *CustomResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	// Create new channels for this call
	resolverChan := make(chan []net.IPAddr, 3)
	errChan := make(chan error, 3)

	// Use a WaitGroup to track goroutines
	var wg sync.WaitGroup
	defer func() {
		wg.Wait()
		close(resolverChan)
		close(errChan)
	}()

	expectedResponses := len(r.dnsServers) + 2 // system + DoH + each DNS server

	// 1. System resolver (parallel)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var systemIPs []net.IPAddr
		if ips4, err := net.DefaultResolver.LookupIP(ctx, "ip4", host); err == nil {
			for _, ip := range ips4 {
				systemIPs = append(systemIPs, net.IPAddr{IP: ip})
			}
		}
		if ips6, err := net.DefaultResolver.LookupIP(ctx, "ip6", host); err == nil {
			for _, ip := range ips6 {
				systemIPs = append(systemIPs, net.IPAddr{IP: ip})
			}
		}
		if len(systemIPs) > 0 {
			select {
			case resolverChan <- systemIPs:
			case <-ctx.Done():
			}
		} else {
			select {
			case errChan <- fmt.Errorf("system resolver returned no IPs"):
			case <-ctx.Done():
			}
		}
	}()

	// 2. Custom DNS servers (parallel)
	for _, server := range r.dnsServers {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: 2 * time.Second}
					return d.DialContext(ctx, "udp", server)
				},
			}
			var dnsIPs []net.IPAddr
			if ips4, err := resolver.LookupIP(ctx, "ip4", host); err == nil {
				for _, ip := range ips4 {
					dnsIPs = append(dnsIPs, net.IPAddr{IP: ip})
				}
			}
			if ips6, err := resolver.LookupIP(ctx, "ip6", host); err == nil {
				for _, ip := range ips6 {
					dnsIPs = append(dnsIPs, net.IPAddr{IP: ip})
				}
			}
			if len(dnsIPs) > 0 {
				select {
				case resolverChan <- dnsIPs:
				case <-ctx.Done():
				}
			} else {
				select {
				case errChan <- fmt.Errorf("DNS server %s returned no IPs", server):
				case <-ctx.Done():
				}
			}
		}(server)
	}

	// 3. DoH resolution (parallel)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var dohIPs []net.IPAddr
		domain := dns.Domain(host)

		// Query A records
		rspA, err := r.dohClient.Query(ctx, domain, dns.TypeA)
		if err == nil && rspA != nil && len(rspA.Answer) > 0 {
			for _, answer := range rspA.Answer {
				if ip := net.ParseIP(answer.Data); ip != nil {
					dohIPs = append(dohIPs, net.IPAddr{IP: ip})
				}
			}
		}

		// Query AAAA records
		rspAAAA, err := r.dohClient.Query(ctx, domain, dns.TypeAAAA)
		if err == nil && rspAAAA != nil && len(rspAAAA.Answer) > 0 {
			for _, answer := range rspAAAA.Answer {
				if ip := net.ParseIP(answer.Data); ip != nil {
					dohIPs = append(dohIPs, net.IPAddr{IP: ip})
				}
			}
		}

		if len(dohIPs) > 0 {
			select {
			case resolverChan <- dohIPs:
			case <-ctx.Done():
			}
		} else {
			select {
			case errChan <- fmt.Errorf("DoH resolution returned no IPs"):
			case <-ctx.Done():
			}
		}
	}()

	// Collector to aggregate unique IPs
	seen := make(map[string]struct{})
	responses := 0
	var ips []net.IPAddr

	// Wait for results or timeout
	for {
		select {
		case resolvedIPs := <-resolverChan:
			responses++
			for _, ip := range resolvedIPs {
				key := ip.IP.String()
				if _, exists := seen[key]; !exists {
					seen[key] = struct{}{}
					ips = append(ips, ip)
				}
			}
		case <-errChan:
			responses++
		case <-ctx.Done():
			if len(ips) > 0 {
				return ips, nil
			}
			return nil, ctx.Err()
		}

		// Break when we have results or all resolvers have responded
		if len(ips) > 0 || responses >= expectedResponses {
			break
		}
	}

	if len(ips) > 0 {
		return ips, nil
	}
	return nil, fmt.Errorf("all DNS resolution attempts failed")
}

// This gets the core dialer instance
func GetSharedDialer() *fasthttp.TCPDialer {
	onceDialer.Do(func() {
		sharedDialer = &fasthttp.TCPDialer{
			Concurrency:      2048,
			DNSCacheDuration: 120 * time.Minute,
			Resolver: NewCustomResolver([]string{
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
			}),
			DisableDNSResolution: false,
		}
	})
	return sharedDialer
}

// This sets the dialer for the  HTTPClient
func CreateDialFunc(timeout time.Duration, proxyURL string) fasthttp.DialFunc {
	// Get shared dialer instance
	dialer := GetSharedDialer()

	return func(addr string) (net.Conn, error) {
		// Handle proxy if configured
		if proxyURL != "" {
			proxyDialer := fasthttpproxy.FasthttpHTTPDialerTimeout(proxyURL, timeout)
			conn, err := proxyDialer(addr)
			if err != nil {
				if handleErr := GB403ErrorHandler.GetErrorHandler().HandleError(err, GB403ErrorHandler.ErrorContext{
					ErrorSource: "Client.proxyDial",
					Host:        addr,
				}); handleErr != nil {
					return nil, fmt.Errorf("proxy dial error handling failed: %v (original error: %v)", handleErr, err)
				}
				return nil, err
			}
			return conn, nil
		}

		// No proxy, use our TCPDialer with timeout
		conn, err := dialer.DialTimeout(addr, timeout)
		if err != nil {
			if handleErr := GB403ErrorHandler.GetErrorHandler().HandleError(err, GB403ErrorHandler.ErrorContext{
				ErrorSource: "Client.directDial",
				Host:        addr,
			}); handleErr != nil {
				return nil, fmt.Errorf("direct dial error handling failed: %v (original error: %v)", handleErr, err)
			}
			return nil, err
		}
		return conn, nil
	}
}

func CreateDialFuncNew(timeout time.Duration, proxyURL string) fasthttp.DialFunc {
	// Get shared dialer instance
	dialer := &fasthttp.TCPDialer{
		Concurrency:      2048,
		DNSCacheDuration: 120 * time.Minute,
	}

	return func(addr string) (net.Conn, error) {
		// Handle proxy if configured
		if proxyURL != "" {
			proxyDialer := fasthttpproxy.FasthttpHTTPDialerTimeout(proxyURL, timeout)
			conn, err := proxyDialer(addr)
			if err != nil {
				if handleErr := GB403ErrorHandler.GetErrorHandler().HandleError(err, GB403ErrorHandler.ErrorContext{
					ErrorSource: "Client.proxyDial",
					Host:        addr,
				}); handleErr != nil {
					return nil, fmt.Errorf("proxy dial error handling failed: %v (original error: %v)", handleErr, err)
				}
				return nil, err
			}
			return conn, nil
		}

		// No proxy, use our TCPDialer with timeout
		conn, err := dialer.DialTimeout(addr, timeout)
		if err != nil {
			if handleErr := GB403ErrorHandler.GetErrorHandler().HandleError(err, GB403ErrorHandler.ErrorContext{
				ErrorSource: "Client.directDial",
				Host:        addr,
			}); handleErr != nil {
				return nil, fmt.Errorf("direct dial error handling failed: %v (original error: %v)", handleErr, err)
			}
			return nil, err
		}
		return conn, nil
	}
}
