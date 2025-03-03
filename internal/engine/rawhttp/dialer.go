package rawhttp

import (
	"net"
	"sync"
	"time"

	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
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
