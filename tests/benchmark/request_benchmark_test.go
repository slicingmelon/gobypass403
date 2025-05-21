// request_timing_test.go
package tests

import (
	"bytes"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
	"github.com/slicingmelon/gobypass403/core/engine/rawhttp"
	"github.com/slicingmelon/gobypass403/core/utils/helpers"
	"github.com/valyala/fasthttp"
)

// 4435408	       280.9 ns/op	       0 B/op	       0 allocs/op
func BenchmarkBuildRawHTTPRequest(b *testing.B) {
	client := rawhttp.NewHTTPClient(rawhttp.DefaultHTTPClientOptions())
	job := payload.BypassPayload{
		Method:       "GET",
		Scheme:       "http",
		Host:         "example.com",
		RawURI:       "/test",
		Headers:      []payload.Headers{{Header: "X-Test", Value: "test-value"}},
		BypassModule: "test-mode",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Move request acquisition inside the parallel function
		req := fasthttp.AcquireRequest()
		defer fasthttp.ReleaseRequest(req)

		for pb.Next() {
			rawhttp.BuildRawHTTPRequest(client, req, job)
		}
	})
}

/*
BenchmarkProcessHTTPResponseStreamed-20         26336985                50.12 ns/op            0 B/op          0 allocs/op
--- BENCH: BenchmarkProcessHTTPResponseStreamed-20

request_benchmark_test.go:68: Response Preview: <!DOCTYPE html><html><head><title>Test Page</title></head><body>test response body</body></html>
request_benchmark_test.go:69: Content Type: text/html
request_benchmark_test.go:70: Title: Test Page
request_benchmark_test.go:68: Response Preview: <!DOCTYPE html><html><head><title>Test Page</title></head><body>test response body</body></html>
request_benchmark_test.go:69: Content Type: text/html
request_benchmark_test.go:70: Title: Test Page
request_benchmark_test.go:68: Response Preview: <!DOCTYPE html><html><head><title>Test Page</title></head><body>test response body</body></html>
request_benchmark_test.go:69: Content Type: text/html
request_benchmark_test.go:70: Title: Test Page
request_benchmark_test.go:68: Response Preview: <!DOCTYPE html><html><head><title>Test Page</title></head><body>test response body</body></html>
... [output truncated]
PASS
*/
func BenchmarkProcessHTTPResponseStreamed(b *testing.B) {
	// Setup client with default options
	opts := rawhttp.DefaultHTTPClientOptions()
	opts.ResponseBodyPreviewSize = 1024
	opts.MaxResponseBodySize = 1024
	client := rawhttp.NewHTTPClient(opts)

	// Create test response with realistic data
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// Setup response data
	resp.SetStatusCode(200)
	resp.Header.SetContentType("text/html")
	resp.Header.Set("Server", "nginx/1.18.0")
	resp.Header.Set("Content-Length", "1024")
	resp.SetBodyStream(bytes.NewReader([]byte(`<!DOCTYPE html><html><head><title>Test Page</title></head><body>test response body</body></html>`)), 1024)

	// Setup test job
	job := payload.BypassPayload{
		Method:       "GET",
		Scheme:       "http",
		Host:         "example.com",
		RawURI:       "/test",
		Headers:      []payload.Headers{{Header: "Accept", Value: "*/*"}},
		BypassModule: "test-mode",
		PayloadToken: "test-token",
	}

	// Verify response processing works correctly before benchmarking
	result := rawhttp.ProcessHTTPResponse(client, resp, job)
	if result == nil {
		b.Fatal("ProcessHTTPResponse returned nil")
	}

	// Debug output to see what we're getting
	b.Logf("Response Preview: %s", result.ResponsePreview)
	b.Logf("Content Type: %s", result.ContentType)
	b.Logf("Title: %s", result.Title)

	// Verify basic response details
	if result.StatusCode != 200 {
		b.Fatalf("Expected status code 200, got %d", result.StatusCode)
	}
	if !bytes.Equal(result.ContentType, []byte("text/html")) {
		b.Fatalf("Expected content-type text/html, got %s", result.ContentType)
	}
	if !bytes.Equal(result.Title, []byte("Test Page")) {
		b.Fatalf("Expected title 'Test Page', got '%s'", result.Title)
	}
	if !bytes.Equal(result.ServerInfo, []byte("nginx/1.18.0")) {
		b.Fatalf("Expected server nginx/1.18.0, got %s", result.ServerInfo)
	}

	rawhttp.ReleaseResponseDetails(result)

	// Run the benchmark
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			result := rawhttp.ProcessHTTPResponse(client, resp, job)
			rawhttp.ReleaseResponseDetails(result)
		}
	})
}

/*
BenchmarkProcessHTTPResponsePerIterationNew-20
21830366	        67.47 ns/op	       0 B/op	       0 allocs/op
PASS
*/
func BenchmarkProcessHTTPResponsePerIterationNew(b *testing.B) {
	opts := rawhttp.DefaultHTTPClientOptions()
	opts.ResponseBodyPreviewSize = 1024
	opts.MaxResponseBodySize = 1024
	client := rawhttp.NewHTTPClient(opts)

	// Setup response once
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	resp.SetStatusCode(200)
	resp.Header.SetContentType("text/html")
	resp.SetBodyStream(bytes.NewReader([]byte(`<!DOCTYPE html><html><head><title>Test Page</title></head><body>test</body></html>`)), 1024)

	job := payload.BypassPayload{
		Method:       "GET",
		Scheme:       "http",
		Host:         "example.com",
		RawURI:       "/test",
		BypassModule: "test-mode",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			result := rawhttp.ProcessHTTPResponse(client, resp, job)
			rawhttp.ReleaseResponseDetails(result)
		}
	})
}

func BenchmarkString2ByteConversion(b *testing.B) {
	s := "test string for conversion benchmark"
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {

		for pb.Next() {
			_ = helpers.String2Byte(s)
		}
	})
}

func BenchmarkByte2StringConversion(b *testing.B) {
	bytes := []byte("test string for conversion benchmark")
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = helpers.Byte2String(bytes)
		}
	})
}

// 167723862	         7.974 ns/op	       0 B/op	       0 allocs/op
func BenchmarkBuildCurlCmd(b *testing.B) {
	job := payload.BypassPayload{
		Method: "POST",
		Scheme: "http",
		Host:   "example.com",
		RawURI: "/test",
		Headers: []payload.Headers{
			{Header: "Content-Type", Value: "application/json"},
			{Header: "Authorization", Value: "Bearer test-token"},
		},
		BypassModule: "test-mode",
	}

	// Create a reusable slice once, outside of the parallel testing
	dest := make([]byte, 0, 512)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Each goroutine gets its own copy to avoid contention
		localDest := make([]byte, 0, len(dest))
		for pb.Next() {
			localDest = rawhttp.BuildCurlCommandWithOpts(job, nil, localDest)
		}

		for pb.Next() {
			localDest = rawhttp.BuildCurlCommandPoc(job, localDest)
		}
	})
}

/*
BenchmarkExtractTitle
BenchmarkExtractTitle/ValidTitle
BenchmarkExtractTitle/ValidTitle-20
42675770	        28.34 ns/op	       0 B/op	       0 allocs/op
BenchmarkExtractTitle/LongTitle
BenchmarkExtractTitle/LongTitle-20
38150343	        30.70 ns/op	       0 B/op	       0 allocs/op
PASS
*/
func BenchmarkExtractTitle(b *testing.B) {
	tests := []struct {
		name string
		html []byte
	}{
		{
			name: "ValidTitle",
			html: []byte(`<!DOCTYPE html><html><head><title>Test Page</title></head><body>test</body></html>`),
		},
		{
			name: "LongTitle",
			html: []byte(`<!DOCTYPE html><html><head><title>Very Long Title That Goes On And On And On And On</title></head><body>test</body></html>`),
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			dest := make([]byte, 0, 64) // Pre-allocate once
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				dest = dest[:0] // Reset length but keep capacity
				dest = rawhttp.ExtractTitle(tt.html, dest)
			}
		})
	}
}

/*
go test -race -bench=BenchmarkBuildRawHTTPRequest -benchmem

6066975	       212.7 ns/op	      48 B/op	       1 allocs/op
BenchmarkBuildRawHTTPRequestNew/ComplexPath
BenchmarkBuildRawHTTPRequestNew/ComplexPath-20
5377290	       218.8 ns/op	      48 B/op	       1 allocs/op
BenchmarkBuildRawHTTPRequestNew/LongHeaders
BenchmarkBuildRawHTTPRequestNew/LongHeaders-20
5043183	       230.7 ns/op	      48 B/op	       1 allocs/op
PASS
*/
func BenchmarkBuildRawHTTPRequestNew(b *testing.B) {
	// Create client options with custom headers
	clientOpts := rawhttp.DefaultHTTPClientOptions()
	clientOpts.CustomHTTPHeaders = []string{
		"X-Client-ID: benchmark-tester",
		"X-Client-Version: 1.0",
		"X-Api-Key: abcdef123456",
		"Cache-Control: no-cache",
		"Accept-Language: en-US,en;q=0.9",
	}

	client := rawhttp.NewHTTPClient(clientOpts)

	// Test cases with different path complexities
	tests := []struct {
		name string
		job  payload.BypassPayload
	}{
		{
			name: "SimpleRequest",
			job: payload.BypassPayload{
				Method:       "GET",
				RawURI:       "/test",
				Host:         "example.com",
				Headers:      []payload.Headers{{Header: "User-Agent", Value: "Go-Bypass-403"}},
				PayloadToken: "test-token",
			},
		},
		{
			name: "ComplexPath",
			job: payload.BypassPayload{
				Method:       "GET",
				RawURI:       "//;/../%2f/。。/test%20space/%252e/",
				Host:         "example.com",
				Headers:      []payload.Headers{{Header: "User-Agent", Value: "Go-Bypass-403"}},
				PayloadToken: "test-token",
			},
		},
		{
			name: "LongHeaders",
			job: payload.BypassPayload{
				Method: "POST",
				RawURI: "/api/test",
				Host:   "example.com",
				Headers: []payload.Headers{
					{Header: "User-Agent", Value: "Go-Bypass-403"},
					{Header: "X-Forward-For", Value: "127.0.0.1"},
					{Header: "Accept", Value: "*/*"},
					{Header: "Accept-Encoding", Value: "gzip, deflate"},
					{Header: "Cookie", Value: "session=abc123; token=xyz789; other=value"},
				},
				PayloadToken: "test-token",
			},
		},
		{
			name: "HeaderConflict",
			job: payload.BypassPayload{
				Method: "GET",
				RawURI: "/api/profile",
				Host:   "example.com",
				Headers: []payload.Headers{
					// This will conflict with client's X-Api-Key and test the merging logic
					{Header: "X-Api-Key", Value: "payload-key-override"},
					{Header: "User-Agent", Value: "Go-Bypass-403"},
				},
				PayloadToken: "test-token",
			},
		},
		{
			name: "CustomHostHeader",
			job: payload.BypassPayload{
				Method: "GET",
				RawURI: "/api/test",
				Host:   "example.com",
				Headers: []payload.Headers{
					{Header: "Host", Value: "evil-host.com"}, // Custom host header
					{Header: "User-Agent", Value: "Go-Bypass-403"},
				},
				PayloadToken: "test-token",
			},
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				// Each goroutine gets its own request object
				req := fasthttp.AcquireRequest()
				defer fasthttp.ReleaseRequest(req)

				for pb.Next() {
					err := rawhttp.BuildRawHTTPRequest(client, req, tt.job)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
