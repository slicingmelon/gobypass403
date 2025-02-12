// request_timing_test.go
package tests

import (
	"bytes"
	"testing"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp"
)

// 4435408	       280.9 ns/op	       0 B/op	       0 allocs/op
func BenchmarkBuildHTTPRequest(b *testing.B) {
	client := rawhttp.NewHTTPClient(rawhttp.DefaultHTTPClientOptions(), nil)
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

// 21029904	        61.35 ns/op	       0 B/op	       0 allocs/op
func BenchmarkProcessHTTPResponseStreamed(b *testing.B) {
	// Setup client with default options
	opts := rawhttp.DefaultHTTPClientOptions()
	opts.ResponseBodyPreviewSize = 1024 // Ensure preview size is large enough
	opts.MaxResponseBodySize = 1024     // Also need to set this
	client := rawhttp.NewHTTPClient(opts, nil)

	// Create test response with realistic data
	resp := client.AcquireResponse()
	defer client.ReleaseResponse(resp)

	// Setup response data
	resp.SetStatusCode(200)
	resp.Header.SetContentType("text/html")
	resp.Header.Set("Server", "nginx/1.18.0")
	resp.Header.Set("Content-Length", "1024")
	resp.SetBodyStream(bytes.NewReader([]byte(`<!DOCTYPE html><html><head><title>Test Page</title></head><body>test response body</body></html>`)), 1024)

	// Setup test job
	job := payload.PayloadJob{
		FullURL:      "http://example.com/test",
		Method:       "GET",
		Headers:      []payload.Headers{{Header: "Accept", Value: "*/*"}},
		BypassModule: "test-mode",
		PayloadToken: "test-token",
	}

	// Verify response processing works correctly before benchmarking
	result := rawhttp.ProcessHTTPResponse(client, resp, job)
	if result == nil {
		b.Fatal("ProcessHTTPResponse returned nil result")
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

// Test both streaming and non-streaming cases
func TestProcessHTTPResponseModes(t *testing.T) {
	tests := []struct {
		name      string
		streaming bool
	}{
		{"NonStreaming", false},
		{"Streaming", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := rawhttp.DefaultHTTPClientOptions()
			opts.StreamResponseBody = tt.streaming
			opts.ResponseBodyPreviewSize = 1024
			client := rawhttp.NewHTTPClient(opts, nil)

			resp := client.AcquireResponse()
			defer client.ReleaseResponse(resp)

			resp.SetStatusCode(200)
			resp.Header.SetContentType("text/html")
			resp.SetBody([]byte(`<!DOCTYPE html><html><head><title>Test Page</title></head><body>test response body</body></html>`))

			job := payload.PayloadJob{
				FullURL:      "http://example.com/test",
				Method:       "GET",
				BypassModule: "test-mode",
			}

			result := rawhttp.ProcessHTTPResponse(client, resp, job)
			if result == nil {
				t.Fatal("ProcessHTTPResponse returned nil result")
			}
			defer rawhttp.ReleaseResponseDetails(result)

			if !bytes.Equal(result.Title, []byte("Test Page")) {
				t.Errorf("Expected title 'Test Page', got '%s'", result.Title)
			}
		})
	}
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

// 167723862	         7.974 ns/op	       0 B/op	       0 allocs/op
func BenchmarkBuildCurlCmd(b *testing.B) {
	job := payload.PayloadJob{
		FullURL:      "http://example.com/test",
		Method:       "POST",
		Headers:      []payload.Headers{{Header: "Content-Type", Value: "application/json"}, {Header: "Authorization", Value: "Bearer test-token"}},
		BypassModule: "test-mode",
	}

	// Create a reusable slice once, outside of the parallel testing
	dest := make([]byte, 0, 512)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Each goroutine gets its own copy to avoid contention
		localDest := make([]byte, 0, len(dest))
		for pb.Next() {
			localDest = rawhttp.BuildCurlCommandPoc(job, localDest)
		}
	})
}
