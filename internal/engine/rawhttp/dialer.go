package rawhttp

// var (
// 	sharedDialer *fasthttp.TCPDialer
// 	onceDialer   sync.Once
// )

// func DefaultDialerOptions() *fasthttp.TCPDialer {
// 	return &fasthttp.TCPDialer{
// 		Concurrency:      2048,
// 		DNSCacheDuration: 120 * time.Minute,
// 	}
// }

// Function to get the shared dialer
// func GetSharedDialer() *fasthttp.TCPDialer {
// 	onceDialer.Do(func() {
// 		// Configure the dialer only once
// 		sharedDialer = &fasthttp.TCPDialer{
// 			Concurrency:      2048,
// 			DNSCacheDuration: 120 * time.Minute,
// 		}
// 	})
// 	return sharedDialer
// }

// func GetSharedDialer() *fasthttp.TCPDialer {
// 	return dialer.GetSharedDialer()
// }

// // CreateDialFunc creates a dial function with the given options and error handler
// func CreateDialFunc(opts *HTTPClientOptions) fasthttp.DialFunc {
// 	if opts.Dialer != nil {
// 		return opts.Dialer
// 	}

// 	// Get shared dialer instance
// 	dialer := GetSharedDialer()

// 	return func(addr string) (net.Conn, error) {
// 		// Handle proxy if configured
// 		if opts.ProxyURL != "" {
// 			proxyDialer := fasthttpproxy.FasthttpHTTPDialerTimeout(opts.ProxyURL, opts.DialTimeout)
// 			conn, err := proxyDialer(addr)
// 			if err != nil {
// 				if handleErr := GB403ErrorHandler.GetErrorHandler().HandleError(err, GB403ErrorHandler.ErrorContext{
// 					ErrorSource: "Client.proxyDial",
// 					Host:        addr,
// 				}); handleErr != nil {
// 					return nil, fmt.Errorf("proxy dial error handling failed: %v (original error: %v)", handleErr, err)
// 				}
// 				return nil, err
// 			}
// 			return conn, nil
// 		}

// 		// No proxy, use our TCPDialer with timeout
// 		conn, err := dialer.DialDualStackTimeout(addr, opts.DialTimeout)
// 		if err != nil {
// 			if handleErr := GB403ErrorHandler.GetErrorHandler().HandleError(err, GB403ErrorHandler.ErrorContext{
// 				ErrorSource: "Client.directDial",
// 				Host:        addr,
// 			}); handleErr != nil {
// 				return nil, fmt.Errorf("direct dial error handling failed: %v (original error: %v)", handleErr, err)
// 			}
// 			return nil, err
// 		}
// 		return conn, nil
// 	}
// }
