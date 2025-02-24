package tests

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

// setupInMemoryServer creates a fasthttp server with in-memory listener
func setupInMemoryServer() (*fasthttp.Server, *fasthttputil.InmemoryListener) {
	ln := fasthttputil.NewInmemoryListener()

	server := &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			ctx.SetStatusCode(fasthttp.StatusOK)
			ctx.SetBodyString("OK")
		},
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	}

	go server.Serve(ln)

	return server, ln
}

// BenchmarkDoRequest benchmarks the DoRequest function with different payload sizes
func BenchmarkDoRequest(b *testing.B) {
	server, ln := setupInMemoryServer()
	defer server.Shutdown()
	defer ln.Close()

	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	client := rawhttp.NewHTTPClient(clientOpts)
	defer client.Close()

	tests := []struct {
		name    string
		payload []byte
	}{
		{"SmallPayload", []byte("small payload")},
		{"MediumPayload", make([]byte, 1024)},     // 1KB
		{"LargePayload", make([]byte, 1024*1024)}, // 1MB
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			bypassPayload := payload.BypassPayload{}

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				// Each goroutine gets its own request and response
				req := fasthttp.AcquireRequest()
				resp := fasthttp.AcquireResponse()
				defer fasthttp.ReleaseRequest(req)
				defer fasthttp.ReleaseResponse(resp)

				req.SetRequestURI("http://localhost")
				req.SetBody(tt.payload)

				for pb.Next() {
					_, err := client.DoRequest(req, resp, bypassPayload)
					if err != nil {
						b.Fatal(err)
					}
					resp.Reset() // Reset response for reuse
				}
			})
		})
	}
}

func BenchmarkDoRequestAllocs(b *testing.B) {
	server, ln := setupInMemoryServer()
	defer server.Shutdown()
	defer ln.Close()

	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	client := rawhttp.NewHTTPClient(clientOpts)
	defer client.Close()

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://localhost")
	req.SetBody([]byte("test"))

	bypassPayload := payload.BypassPayload{}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := client.DoRequest(req, resp, bypassPayload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDoRequestAllocsDetailed(b *testing.B) {
	server, ln := setupInMemoryServer()
	defer server.Shutdown()
	defer ln.Close()

	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	client := rawhttp.NewHTTPClient(clientOpts)
	defer client.Close()

	// Track individual components with ReportAllocs
	b.Run("setup", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := fasthttp.AcquireRequest()
			resp := fasthttp.AcquireResponse()
			req.SetRequestURI("http://localhost")
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
		}
	})

	b.Run("payload", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = payload.BypassPayload{}
		}
	})

	// Full request with tracing
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI("http://localhost")
	bypassPayload := payload.BypassPayload{}

	b.Run("full_request", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := client.DoRequest(req, resp, bypassPayload)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkRequestComponents(b *testing.B) {
	server, ln := setupInMemoryServer()
	defer server.Shutdown()
	defer ln.Close()

	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	client := rawhttp.NewHTTPClient(clientOpts)
	defer client.Close()

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI("http://localhost")
	bypassPayload := payload.BypassPayload{}

	b.Run("just_request_copy", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			reqCopy := fasthttp.AcquireRequest()
			rawhttp.ReqCopyToWithSettings(req, reqCopy)
			fasthttp.ReleaseRequest(reqCopy)
		}
	})

	b.Run("just_do_request", func(b *testing.B) {
		b.ReportAllocs()
		reqCopy := fasthttp.AcquireRequest()
		rawhttp.ReqCopyToWithSettings(req, reqCopy)
		for i := 0; i < b.N; i++ {
			_, err := client.DoRequest(reqCopy, resp, bypassPayload)
			if err != nil {
				b.Fatal(err)
			}
		}
		fasthttp.ReleaseRequest(reqCopy)
	})

	b.Run("error_context_with_handler", func(b *testing.B) {
		b.ReportAllocs()
		testErr := fmt.Errorf("test error")
		for i := 0; i < b.N; i++ {
			errCtx := GB403ErrorHandler.ErrorContext{
				ErrorSource:  "execFunc",
				Host:         payload.BypassPayloadToBaseURL(bypassPayload),
				BypassModule: bypassPayload.BypassModule,
				DebugToken:   bypassPayload.PayloadToken,
			}
			_ = GB403ErrorHandler.GetErrorHandler().HandleError(testErr, errCtx)
		}
	})
}

// BenchmarkDoRequestWithRetry benchmarks DoRequest with retry mechanism
func BenchmarkDoRequestWithRetry(b *testing.B) {
	var failCount int32
	server := &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			if atomic.AddInt32(&failCount, 1)%3 == 0 {
				ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
				return
			}
			ctx.SetStatusCode(fasthttp.StatusOK)
			ctx.SetBodyString("OK")
		},
	}

	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	go server.Serve(ln)
	defer server.Shutdown()

	clientOpts := &rawhttp.HTTPClientOptions{
		Timeout:    5 * time.Second,
		MaxRetries: 3,
		RetryDelay: 100 * time.Millisecond,
		Dialer: func(addr string) (net.Conn, error) {
			return ln.Dial()
		},
	}

	client := rawhttp.NewHTTPClient(clientOpts)
	defer client.Close()

	bypassPayload := payload.BypassPayload{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := fasthttp.AcquireRequest()
		req.SetRequestURI("http://localhost")

		_, err := client.DoRequest(req, nil, bypassPayload)
		if err != nil {
			b.Fatal(err)
		}

		fasthttp.ReleaseRequest(req)
	}
}

// BenchmarkDoRequestWithDifferentMethods benchmarks different HTTP methods
func BenchmarkDoRequestWithDifferentMethods(b *testing.B) {
	server, ln := setupInMemoryServer()
	defer server.Shutdown()
	defer ln.Close()

	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	client := rawhttp.NewHTTPClient(clientOpts)
	defer client.Close()

	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}
	bypassPayload := payload.BypassPayload{}

	//rawhttp.BuildRawHTTPRequest(client, req, bypassPayload)

	for _, method := range methods {
		b.Run(method, func(b *testing.B) {
			req := fasthttp.AcquireRequest()
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseRequest(req)
			defer fasthttp.ReleaseResponse(resp)

			req.SetRequestURI("http://localhost")
			req.Header.SetMethod(method)

			if method == "POST" || method == "PUT" {
				req.SetBody([]byte("test body"))
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := client.DoRequest(req, resp, bypassPayload) // Use resp instead of nil
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDoRequestWithHeaders benchmarks requests with different header sizes
func BenchmarkDoRequestWithHeaders(b *testing.B) {
	server, ln := setupInMemoryServer()
	defer server.Shutdown()
	defer ln.Close()

	client := rawhttp.NewHTTPClient(rawhttp.DefaultHTTPClientOptions())
	defer client.Close()

	tests := []struct {
		name         string
		headerCount  int
		headerLength int
	}{
		{"SmallHeaders", 5, 10},
		{"MediumHeaders", 20, 50},
		{"LargeHeaders", 50, 100},
	}

	bypassPayload := payload.BypassPayload{}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			req := fasthttp.AcquireRequest()
			defer fasthttp.ReleaseRequest(req)

			req.SetRequestURI("http://localhost")

			// Add headers
			for i := 0; i < tt.headerCount; i++ {
				headerValue := make([]byte, tt.headerLength)
				req.Header.Set(fmt.Sprintf("Header-%d", i), string(headerValue))
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := client.DoRequest(req, nil, bypassPayload)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
