package tests

import (
	"net"
	"testing"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func BenchmarkProcessRequests(b *testing.B) {
	// Create pool with all dependencies properly initialized
	pool := rawhttp.NewRequestWorkerPool(rawhttp.DefaultHTTPClientOptions(), 10, nil)

	// Create test response
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// Setup response data
	resp.SetStatusCode(200)
	resp.SetBody([]byte("<!DOCTYPE html><html><head><title>Test Page</title></head><body>test response body</body></html>"))
	resp.Header.SetContentType("text/html")
	resp.Header.Set("Server", "test-server")

	// Setup test job
	job := payload.PayloadJob{
		FullURL:      "http://example.com/test",
		Method:       "GET",
		Headers:      []payload.Headers{{Header: "Accept", Value: "*/*"}},
		BypassModule: "test-mode",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pool.ProcessRequests([]payload.PayloadJob{job})
		}
	})
}

func BenchmarkProcessRequests2(b *testing.B) {
	pool := rawhttp.NewRequestWorkerPool(rawhttp.DefaultHTTPClientOptions(), 10, nil)

	baseJob := payload.PayloadJob{
		FullURL:      "http://example.com/test",
		Method:       "GET",
		Headers:      []payload.Headers{{Header: "Accept", Value: "*/*"}},
		BypassModule: "test-mode",
	}

	jobs := make([]payload.PayloadJob, 2000)
	for i := range jobs {
		jobs[i] = baseJob
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			count := 0
			for range pool.ProcessRequests(jobs) {
				count++
			}
			// Optionally verify count if needed
			// if count == 0 {
			//     b.Fatal("No results received")
			// }
		}
	})
}

func BenchmarkProcessRequests3(b *testing.B) {
	// Setup mock server
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Start mock server
	go func() {
		err := fasthttp.Serve(ln, func(ctx *fasthttp.RequestCtx) {
			ctx.SetStatusCode(200)
			ctx.SetBodyString("<!DOCTYPE html><html><head><title>Test Page</title></head><body>test response body</body></html>")
			ctx.Response.Header.SetContentType("text/html")
			ctx.Response.Header.Set("Server", "test-server")
		})
		if err != nil {
			b.Error(err)
		}
	}()

	// Create custom client options with mock dialer
	opts := rawhttp.DefaultHTTPClientOptions()
	opts.Dialer = func(addr string) (net.Conn, error) {
		return ln.Dial()
	}

	pool := rawhttp.NewRequestWorkerPool(opts, 10, nil)
	defer pool.Close()

	baseJob := payload.PayloadJob{
		FullURL:      "http://example.com/test",
		Method:       "GET",
		Headers:      []payload.Headers{{Header: "Accept", Value: "*/*"}},
		BypassModule: "test-mode",
	}

	jobs := make([]payload.PayloadJob, 2000)
	for i := range jobs {
		jobs[i] = baseJob
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			count := 0
			for result := range pool.ProcessRequests(jobs) {
				if result != nil {
					count++
				}
			}
			if count == 0 {
				b.Error("No results received")
			}
		}
	})
}
