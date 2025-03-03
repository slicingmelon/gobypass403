package rawhttp

import (
	"net"
	"sync"
	"time"

	tls "github.com/refraction-networking/utls"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
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

// Define limited set of HelloIDs for browser fingerprinting
var (
	helloIDs = []tls.ClientHelloID{
		tls.HelloChrome_Auto,
		tls.HelloFirefox_Auto,
		tls.HelloSafari_Auto,
	}
)

func GetRandomHelloID() tls.ClientHelloID {
	return helloIDs[time.Now().UnixNano()%int64(len(helloIDs))]
}

// CreateUTLSDialer creates a dialer that uses uTLS for TLS connections
func CreateUTLSDialer(timeout time.Duration, proxyURL string) fasthttp.DialFunc {
	baseDialer := &fasthttp.TCPDialer{
		Concurrency:      4096,
		DNSCacheDuration: time.Hour,
	}

	return func(addr string) (net.Conn, error) {
		// First, establish a TCP connection
		tcpConn, err := baseDialer.Dial(addr)
		//tcpConn, err := net.Dial("tcp", addr)
		if err != nil {
			GB403Logger.Error().Msgf("[CreateUTLSDialer] TCP connection failed: %v\n\n", err)
			return nil, err
		}

		// For non-TLS connections, return the TCP connection as is
		// if !strings.Contains(addr, ":443") {
		// 	return tcpConn, nil
		// }

		// For TLS connections, wrap with uTLS
		//serverName := strings.Split(addr, ":")[0]
		//helloID := GetRandomHelloID()

		// Create a uTLS connection with the TCP connection
		// tlsConn := tls.UClient(tcpConn, &tls.Config{
		// 	//ServerName:         serverName,
		// 	InsecureSkipVerify: true, // Skip certificate verification for pentest purposes
		// 	//MinVersion:         tls.VersionTLS10,
		// 	//MaxVersion:         tls.VersionTLS13,
		// 	OmitEmptyPsk: true,
		// }, helloID)

		tlsConn := tls.UClient(tcpConn, &tls.Config{
			//ServerName:         serverName,
			InsecureSkipVerify: true, // Skip certificate verification for pentest purposes
			//MinVersion:         tls.VersionTLS10,
			//MaxVersion:         tls.VersionTLS13,
			OmitEmptyPsk: true,
		}, tls.HelloRandomized)

		// Perform TLS handshake
		if err := tlsConn.Handshake(); err != nil {
			GB403Logger.Error().Msgf("[CreateUTLSDialer] TLS handshake failed: %v\n\n", err)
			tcpConn.Close()
			return nil, err
		}

		return tlsConn, nil
	}
}

// This sets the dialer for the HTTPClient
func CreateHTTPClientDialer(timeout time.Duration, proxyURL string) fasthttp.DialFunc {

	dialer := GetHTTPClientSharedDialer()

	return func(addr string) (net.Conn, error) {
		//GB403Logger.Debug().Msgf("[CreateHTTPClientDialer] Attempting to dial address: %s\n", addr)

		// Handle proxy if configured
		if proxyURL != "" {
			proxyDialer := fasthttpproxy.FasthttpHTTPDialerTimeout(proxyURL, timeout)
			conn, err := proxyDialer(addr)
			if err != nil {
				// If it's a whitelisted error, HandleError returns nil
				if handledErr := GB403ErrorHandler.GetErrorHandler().HandleError(err, GB403ErrorHandler.ErrorContext{
					ErrorSource: "Client.proxyDial",
					Host:        addr,
				}); handledErr == nil {
					// This was a whitelisted error, we can ignore it
					return nil, nil
				}
				// Not whitelisted, return just the original error
				return nil, err
			}
			return conn, nil
		}

		// No proxy, use our TCPDialer with timeout
		conn, err := dialer.DialDualStackTimeout(addr, timeout)
		if err != nil {
			// If it's a whitelisted error, HandleError returns nil
			if handledErr := GB403ErrorHandler.GetErrorHandler().HandleError(err, GB403ErrorHandler.ErrorContext{
				ErrorSource: "Client.directDial",
				Host:        addr,
			}); handledErr == nil {
				// This was a whitelisted error, we can ignore it
				return nil, nil
			}
			// Not whitelisted, return just the original error
			return nil, err
		}
		return conn, nil
	}
}
