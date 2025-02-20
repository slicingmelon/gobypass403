package main

import (
	"context"
	"fmt"
	"net"
	"time"
)

func main() {
	// Define the DNS server
	dnsServer := "8.8.8.8:53" // Google's public DNS server over UDP

	// Create a custom resolver with a specific DNS server (8.8.8.8)
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Use UDP to resolve through 8.8.8.8
			conn, err := net.DialTimeout(network, dnsServer, 2*time.Second)
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
	}

	// Domain to resolve
	domain := "www.pornhub.com"

	// Resolve the domain
	ips, err := resolver.LookupIPAddr(context.Background(), domain)
	if err != nil {
		fmt.Printf("Failed to resolve %s: %v\n", domain, err)
		return
	}

	// Print the resolved IP addresses
	fmt.Printf("Resolved %s:\n", domain)
	for _, ip := range ips {
		fmt.Println(ip.String())
	}
}
