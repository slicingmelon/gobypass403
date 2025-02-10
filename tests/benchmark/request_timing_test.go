// request_timing_test.go
package tests

import (
	"testing"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	"github.com/valyala/fasthttp"
)

func BenchmarkBuildHTTPRequest(b *testing.B) {
	client := rawhttp.NewHTTPClient(rawhttp.DefaultHTTPClientOptions(), GB403ErrorHandler.NewErrorHandler(32))
	job := payload.PayloadJob{
		FullURL:      "http://example.com/test",
		Method:       "GET",
		Headers:      []payload.Headers{{Header: "X-Test", Value: "test-value"}},
		BypassModule: "test-mode",
	}

	req := client.AcquireRequest()
	defer client.ReleaseRequest(req)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rawhttp.BuildHTTPRequest(client, req, job)
		}
	})
}

func BenchmarkProcessRequests(b *testing.B) {
	// Create pool with all dependencies properly initialized
	pool := rawhttp.NewRequestWorkerPool(rawhttp.DefaultHTTPClientOptions(), 10, GB403ErrorHandler.NewErrorHandler(32))

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
		Headers:      []payload.Headers{{Header: "Content-Type", Value: "application/json"}, {Header: "Authorization", Value: "Bearer test-token"}},
		BypassModule: "test-mode",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rawhttp.BuildCurlCommandPoc(job)
		}
	})
}
