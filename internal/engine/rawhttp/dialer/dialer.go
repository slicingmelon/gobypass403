package dialer

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/likexian/doh"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
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
		sharedDialer = &fasthttp.TCPDialer{
			Concurrency:      2048,
			DNSCacheDuration: 120 * time.Minute,
		}
	})
	return sharedDialer
}

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
		conn, err := dialer.DialDualStackTimeout(addr, timeout)
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

// func GetSharedDialer() *fasthttp.TCPDialer {
// 	onceDialer.Do(func() {
// 		// Initialize DoH client
// 		dohClient = doh.Use(doh.CloudflareProvider, doh.GoogleProvider)

// 		sharedDialer = &fasthttp.TCPDialer{
// 			Concurrency:      2048,
// 			DNSCacheDuration: 120 * time.Minute,
// 			Resolver: &net.Resolver{
// 				PreferGo: true,
// 				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
// 					// Try DialDualStack first
// 					if conn, err := sharedDialer.DialDualStackTimeout(address, 5*time.Second); err == nil {
// 						return conn, nil
// 					}

// 					// If DialDualStack fails, try DoH
// 					host := address
// 					if h, _, err := net.SplitHostPort(address); err == nil {
// 						host = h
// 					}

// 					rsp, err := dohClient.Query(ctx, dns.Domain(host), dns.TypeA)
// 					if err == nil && len(rsp.Answer) > 0 {
// 						for _, a := range rsp.Answer {
// 							if conn, err := sharedDialer.DialDualStackTimeout(a.Data, 5*time.Second); err == nil {
// 								return conn, nil
// 							}
// 						}
// 					}

// 					return nil, fmt.Errorf("all resolution methods failed for %s", address)
// 				},
// 			},
// 		}
// 	})
// 	return sharedDialer
// }

// CreateDialFunc creates a dial function with the given options and error handler

// // Cleanup function
// func Cleanup() {
// 	if dohClient != nil {
// 		dohClient.Close()
// 	}
// // // Cleanup function
// func Cleanup() {
// 	if dohClient != nil {
// 		dohClient.Close()
// 	}
// }
