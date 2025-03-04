package rawhttp

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
)

var (
	clientSharedDialer *fasthttp.TCPDialer
	onceClientDialer   sync.Once
)

func GetHTTPClientSharedDialer() *fasthttp.TCPDialer {
	onceClientDialer.Do(func() {
		clientSharedDialer = &fasthttp.TCPDialer{
			Concurrency:      2048,
			DNSCacheDuration: 120 * time.Minute,
		}
	})
	return clientSharedDialer
}

// // Define limited set of HelloIDs for browser fingerprinting
// var (
// 	helloIDs = []tls.ClientHelloID{
// 		tls.HelloChrome_Auto,
// 		tls.HelloFirefox_Auto,
// 		tls.HelloSafari_Auto,
// 	}
// )

// func GetRandomHelloID() tls.ClientHelloID {
// 	return helloIDs[time.Now().UnixNano()%int64(len(helloIDs))]
// }

// type TLSContext struct {
// 	mu    sync.RWMutex
// 	hosts map[string]bool // maps "host:port" -> isTLS
// }

// // NewTLSContext creates a new TLSContext
// func NewTLSContext() *TLSContext {
// 	return &TLSContext{
// 		hosts: make(map[string]bool),
// 	}
// }

// // SetTLS sets whether a host:port should use TLS
// func (t *TLSContext) SetTLS(hostPort string, isTLS bool) {
// 	t.mu.Lock()
// 	defer t.mu.Unlock()
// 	t.hosts[hostPort] = isTLS
// }

// // IsTLS checks if a host:port should use TLS
// func (t *TLSContext) IsTLS(hostPort string) bool {
// 	t.mu.RLock()
// 	defer t.mu.RUnlock()
// 	return t.hosts[hostPort]
// }

// // CreateUTLSDialer creates a dialer that uses uTLS for TLS connections
// func CreateUTLSDialer(tlsContext *TLSContext, timeout time.Duration, proxyURL string) fasthttp.DialFunc {

// 	baseDialer := &fasthttp.TCPDialer{
// 		Concurrency:      4096,
// 		DNSCacheDuration: time.Hour,
// 	}

// 	return func(addr string) (net.Conn, error) {
// 		// First establish TCP connection

// 		GB403Logger.Info().Msgf("[CreateUTLSDialer] Dialing address: %s\n", addr)

// 		tcpConn, err := baseDialer.DialDualStack(addr)
// 		if err != nil {
// 			return nil, err
// 		}

// 		// Check if this connection should use TLS
// 		isTLS := tlsContext.IsTLS(addr)

// 		// Check if connection is already TLS
// 		_, isTLSAlready := tcpConn.(interface{ Handshake() error })

// 		// If we need TLS and it's not already TLS
// 		if isTLS && !isTLSAlready {
// 			serverName := strings.Split(addr, ":")[0]

// 			tlsConn := tls.UClient(tcpConn, &tls.Config{
// 				ServerName:         serverName,
// 				InsecureSkipVerify: true,
// 				OmitEmptyPsk:       true,
// 			}, tls.HelloRandomizedALPN)

// 			if err := tlsConn.Handshake(); err != nil {
// 				GB403Logger.Error().Msgf("[CreateUTLSDialer] Failed to handshake: %v\n\n", err)
// 				tcpConn.Close()
// 				return nil, err
// 			}

// 			return tlsConn, nil
// 		}

// 		// For non-TLS connections, return the TCP connection as is
// 		return tcpConn, nil
// 	}
// }

// This sets the dialer for the HTTPClient
// func CreateHTTPClientDialer(timeout time.Duration, proxyURL string) fasthttp.DialFunc {

// 	dialer := GetHTTPClientSharedDialer()

// 	return func(addr string) (net.Conn, error) {
// 		//GB403Logger.Debug().Msgf("[CreateHTTPClientDialer] Attempting to dial address: %s\n", addr)

// 		// Handle proxy if configured
// 		if proxyURL != "" {
// 			proxyDialer := fasthttpproxy.FasthttpHTTPDialerTimeout(proxyURL, timeout)
// 			conn, err := proxyDialer(addr)
// 			if err != nil {
// 				// If it's a whitelisted error, HandleError returns nil
// 				if handledErr := GB403ErrorHandler.GetErrorHandler().HandleError(err, GB403ErrorHandler.ErrorContext{
// 					ErrorSource: "Client.proxyDial",
// 					Host:        addr,
// 				}); handledErr == nil {
// 					// This was a whitelisted error, we can ignore it
// 					return nil, nil
// 				}
// 				// Not whitelisted, return just the original error
// 				return nil, err
// 			}
// 			return conn, nil
// 		}

// 		// No proxy, use our TCPDialer with timeout
// 		conn, err := dialer.DialDualStackTimeout(addr, timeout)
// 		if err != nil {
// 			// If it's a whitelisted error, HandleError returns nil
// 			if handledErr := GB403ErrorHandler.GetErrorHandler().HandleError(err, GB403ErrorHandler.ErrorContext{
// 				ErrorSource: "Client.directDial",
// 				Host:        addr,
// 			}); handledErr == nil {
// 				// This was a whitelisted error, we can ignore it
// 				return nil, nil
// 			}
// 			// Not whitelisted, return just the original error
// 			return nil, err
// 		}
// 		return conn, nil
// 	}
// }

func CreateHTTPClientDialer(timeout time.Duration, proxyURL string) fasthttp.DialFunc {
	dialer := GetHTTPClientSharedDialer()

	return func(addr string) (net.Conn, error) {
		// Handle proxy if configured
		if proxyURL != "" {
			proxyDialer := fasthttpproxy.FasthttpHTTPDialerTimeout(proxyURL, timeout)
			conn, err := proxyDialer(addr)
			if err != nil {
				return nil, fmt.Errorf("[Client.proxyDial] %s: %w", addr, err)
			}
			return conn, nil
		}

		// No proxy, use our TCPDialer with timeout
		conn, err := dialer.DialDualStackTimeout(addr, timeout)
		if err != nil {
			return nil, fmt.Errorf("[Client.directDial] %s: %w", addr, err)
		}
		return conn, nil
	}
}
