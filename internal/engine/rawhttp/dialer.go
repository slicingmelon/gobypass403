package rawhttp

import (
	"fmt"
	"net"
	"sync"
	"time"

	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
)

var (
	sharedDialer *fasthttp.TCPDialer
	onceDialer   sync.Once
)

func DefaultDialerOptions() *fasthttp.TCPDialer {
	return &fasthttp.TCPDialer{
		Concurrency:      2048,
		DNSCacheDuration: 60 * time.Minute,
	}
}

// Function to get the shared dialer
func GetSharedDialer() *fasthttp.TCPDialer {
	onceDialer.Do(func() {
		// Configure the dialer only once
		sharedDialer = &fasthttp.TCPDialer{
			Concurrency:      2048,
			DNSCacheDuration: 60 * time.Minute,
		}
	})
	return sharedDialer
}

// CreateDialFunc creates a dial function with the given options and error handler
func CreateDialFunc(opts *HTTPClientOptions) fasthttp.DialFunc {
	if opts.Dialer != nil {
		return opts.Dialer
	}

	// Create default dialer
	dialer := GetSharedDialer()

	return func(addr string) (net.Conn, error) {
		if opts.ProxyURL != "" {
			proxyDialer := fasthttpproxy.FasthttpHTTPDialerTimeout(opts.ProxyURL, opts.DialTimeout)
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
		// DialTimeout dials the given TCP addr using tcp4 using the given timeout.
		// This function has the following additional features comparing to net.Dial:
		//	It reduces load on DNS resolver by caching resolved TCP addressed for DNSCacheDuration.
		//	It dials all the resolved TCP addresses in round-robin manner until connection is established. This may be useful if certain addresses are temporarily unreachable.
		// This dialer is intended for custom code wrapping before passing to Client.DialTimeout or HostClient.DialTimeout.
		// For instance, per-host counters and/or limits may be implemented by such wrappers.
		// The addr passed to the function must contain port. Example addr values:
		// foobar.baz:443
		// foo.bar:80
		// aaa.com:8080
		conn, err := dialer.DialDualStackTimeout(addr, opts.DialTimeout)
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
