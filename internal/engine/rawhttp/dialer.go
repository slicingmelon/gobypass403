package rawhttp

import (
	"fmt"
	"net"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/engine/recon"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
)

// DefaultDialer returns the default dialer configuration
func DefaultDialer() *fasthttp.TCPDialer {
	return &fasthttp.TCPDialer{
		Concurrency:      2048,
		DNSCacheDuration: 60 * time.Minute,
	}
}

// SetDialer sets a custom dialer for the client
func (c *HTTPClient) SetDialer(dialer fasthttp.DialFunc) *HTTPClient {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.client != nil {
		c.client.Dial = dialer
	}
	return c
}

// CreateDialFunc creates a dial function with the given options and error handler
func CreateDialFunc(opts *HTTPClientOptions) fasthttp.DialFunc {
	if opts.Dialer != nil {
		return opts.Dialer
	}

	reconDialer := recon.GetReconInstance().GetDialer()
	GB403Logger.Debug().Msgf("Creating dial func with recon dialer: %v", reconDialer != nil)

	return func(addr string) (net.Conn, error) {
		GB403Logger.Debug().Msgf("Dialing address: %s", addr)

		if opts.ProxyURL != "" {
			return handleProxyDial(opts, addr)
		}

		// Use recon's dialer which already includes robust DNS resolution
		conn, err := reconDialer.DialDualStackTimeout(addr, opts.DialTimeout)
		if err != nil {
			GB403Logger.Error().Msgf("Dial error for %s: %v", addr, err)
			if handleErr := GB403ErrorHandler.GetErrorHandler().HandleError(err, GB403ErrorHandler.ErrorContext{
				ErrorSource: "Client.directDial",
				Host:        addr,
			}); handleErr != nil {
				return nil, fmt.Errorf("direct dial error handling failed: %v (original error: %v)", handleErr, err)
			}
			return nil, err
		}

		GB403Logger.Debug().Msgf("Successfully connected to %s", addr)
		return conn, nil
	}
}

func handleProxyDial(opts *HTTPClientOptions, addr string) (net.Conn, error) {
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

	// Set TCP keep-alive for proxy connections
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	return conn, nil
}
