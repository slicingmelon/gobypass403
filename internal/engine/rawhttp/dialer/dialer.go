package dialer

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/likexian/doh"
	"github.com/likexian/doh/dns"
	"github.com/valyala/fasthttp"
)

var (
	sharedDialer *fasthttp.TCPDialer
	onceDialer   sync.Once
	dohClient    *doh.DoH // Hold DoH client instance
)

func init() {
	// Initialize DoH client once
	dohClient = doh.Use(doh.CloudflareProvider, doh.GoogleProvider)
}

func GetSharedDialer() *fasthttp.TCPDialer {
	onceDialer.Do(func() {
		// Initialize DoH client
		dohClient = doh.Use(doh.CloudflareProvider, doh.GoogleProvider)

		sharedDialer = &fasthttp.TCPDialer{
			Concurrency:      2048,
			DNSCacheDuration: 120 * time.Minute,
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					// Try system resolver first
					d := net.Dialer{Timeout: 2 * time.Second}
					if conn, err := d.DialContext(ctx, network, address); err == nil {
						return conn, nil
					}

					// If system resolver fails, try DoH
					host := address
					if h, _, err := net.SplitHostPort(address); err == nil {
						host = h
					}

					rsp, err := dohClient.Query(ctx, dns.Domain(host), dns.TypeA)
					if err == nil && len(rsp.Answer) > 0 {
						// Try each IP from DoH response
						for _, a := range rsp.Answer {
							if conn, err := d.DialContext(ctx, network, a.Data); err == nil {
								return conn, nil
							}
						}
					}

					return nil, fmt.Errorf("all resolution methods failed for %s", address)
				},
			},
		}
	})
	return sharedDialer
}

// Cleanup function
func Cleanup() {
	if dohClient != nil {
		dohClient.Close()
	}
}

// func ConfigureResolver(dialer *fasthttp.TCPDialer, dnsServer string) {
// 	dialer.Resolver = &net.Resolver{
// 		PreferGo: true,
// 		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
// 			// Try UDP first
// 			d := net.Dialer{Timeout: 2 * time.Second}
// 			if conn, err := d.DialContext(ctx, "udp", dnsServer); err == nil {
// 				return conn, nil
// 			}

// 			// If UDP fails, try TCP
// 			if conn, err := d.DialContext(ctx, "tcp", dnsServer); err == nil {
// 				return conn, nil
// 			}

// 			// If both UDP and TCP fail, use DoH as last resort
// 			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// 			defer cancel()

// 			// Create new DoH client for this request
// 			c := doh.Use(doh.CloudflareProvider, doh.GoogleProvider)
// 			defer c.Close()

// 			rsp, err := c.Query(ctx, dns.Domain(address), dns.TypeA)
// 			if err != nil {
// 				return nil, err
// 			}

// 			// Try to connect using resolved IPs
// 			for _, a := range rsp.Answer {
// 				if conn, err := d.DialContext(ctx, "tcp", a.Data); err == nil {
// 					return conn, nil
// 				}
// 			}

// 			return nil, fmt.Errorf("all resolution methods failed")
// 		},
// 	}
// }

// // Cleanup function to be called when shutting down
// func Cleanup() {
// 	if dohClient != nil {
// 		dohClient.Close()
// 	}
// }

// // Don't forget to clean up
// func cleanup() {
// 	if dohClient != nil {
// 		dohClient.Close()
// 	}
// }
