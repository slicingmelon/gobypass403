// request_timing_test.go
package tests

import (
	"testing"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	"github.com/valyala/fasthttp"
)

func BenchmarkRequestBuilder_BuildRequest(b *testing.B) {
	client := rawhttp.NewHTTPClient(rawhttp.DefaultOptionsSameHost(), GB403ErrorHandler.NewErrorHandler(32))
	builder := rawhttp.NewRequestBuilder(client)
	job := payload.PayloadJob{
		FullURL:      "http://example.com/test",
		Method:       "GET",
		Headers:      []payload.Header{{Header: "X-Test", Value: "test-value"}},
		BypassModule: "test-mode",
	}

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			builder.BuildRequest(req, job)
		}
	})
}

func BenchmarkProcessResponse(b *testing.B) {
	pool := rawhttp.NewRequestPool(rawhttp.DefaultOptionsSameHost(), &rawhttp.ScannerCliOpts{
		ResponseBodyPreviewSize: 100,
	}, GB403ErrorHandler.NewErrorHandler(32))

	// Prepare a response for benchmarking
	resp := fasthttp.AcquireResponse()
	resp.SetStatusCode(200)
	resp.SetBody([]byte("test response body"))
	resp.Header.SetContentType("text/plain")
	resp.Header.Set("Server", "test-server")

	job := payload.PayloadJob{
		FullURL:      "http://example.com/test",
		BypassModule: "test-mode",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pool.ProcessRequests([]payload.PayloadJob{job})
		}
	})
}

func BenchmarkString2ByteConversion(b *testing.B) {
	s := "test string for conversion benchmark"
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = rawhttp.String2Byte(s)
		}
	})
}

func BenchmarkByte2StringConversion(b *testing.B) {
	bytes := []byte("test string for conversion benchmark")
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = rawhttp.Byte2String(bytes)
		}
	})
}

func BenchmarkBuildCurlCmd(b *testing.B) {
	job := payload.PayloadJob{
		FullURL:      "http://example.com/test",
		Method:       "POST",
		Headers:      []payload.Header{{Header: "Content-Type", Value: "application/json"}, {Header: "Authorization", Value: "Bearer test-token"}},
		BypassModule: "test-mode",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rawhttp.BuildCurlCommandPoc(job)
		}
	})
}

// Worker pool specific benchmarks
func BenchmarkRequestPool_ProcessRequests(b *testing.B) {
	pool := rawhttp.NewRequestPool(rawhttp.DefaultOptionsSameHost(), &rawhttp.ScannerCliOpts{
		ResponseBodyPreviewSize: 100,
	}, GB403ErrorHandler.NewErrorHandler(32))

	jobs := make([]payload.PayloadJob, 100)
	for i := range jobs {
		jobs[i] = payload.PayloadJob{
			FullURL:      "http://example.com/test",
			Method:       "GET",
			BypassModule: "test-mode",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results := pool.ProcessRequests(jobs)
		for range results {
			// drain the channel
		}
	}
}
