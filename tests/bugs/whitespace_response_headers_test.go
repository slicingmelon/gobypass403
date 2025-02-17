package tests

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
	"github.com/slicingmelon/go-rawurlparser"
	"github.com/valyala/fasthttp"
)

func TestWhitespaceResponseHeaders(t *testing.T) {
	// Create fasthttp client with specified configuration
	client := &fasthttp.Client{
		StreamResponseBody:            false,
		DisablePathNormalizing:        true,
		DisableHeaderNamesNormalizing: true,

		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxResponseBodySize: 8092 * 2,
		ReadBufferSize:      8092 * 2,
		WriteBufferSize:     8092 * 2,
	}

	// Prepare request
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()

	req.URI().DisablePathNormalizing = true
	req.Header.DisableNormalizing()
	req.Header.SetNoDefaultContentType(true)

	// Set request URL with special character
	req.SetRequestURI("https://examplffsdf221.mp4%26/")

	// Make the request
	err := client.Do(req, resp)

	// fmt.Printf("Request error: %v\n", err)
	// body := resp.BodyStream()
	// fmt.Printf("Body: %v\n", body)

	if err != nil {
		fmt.Printf("Request error: %v\n", err)

		t.Fail()
	}
}

// go.exe test -race -timeout 30s -run ^TestResponseHandlingRaces$ github.com/slicingmelon/go-bypass-403/tests/bugs -v
func TestResponseHandlingRaces(t *testing.T) {
	httpClientOpts := rawhttp.DefaultHTTPClientOptions()
	httpClientOpts.RequestDelay = 700 * time.Millisecond
	errorHandler := GB403ErrorHandler.GetErrorHandler()
	client := rawhttp.NewHTTPClient(httpClientOpts)
	// Create a test server that returns malformed responses
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate malformed response
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte("\x95^;\xbb\xaa\x9a\x15")) // Malformed data
	}))
	defer ts.Close()

	// Run multiple goroutines to simulate concurrent requests
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			req := client.AcquireRequest()
			resp := client.AcquireResponse()
			defer client.ReleaseRequest(req)
			defer client.ReleaseResponse(resp)

			req.SetRequestURI(ts.URL)

			job := payload.PayloadJob{
				Host:         ts.URL,
				BypassModule: "test",
				PayloadToken: "test-token",
			}

			_, err := client.DoRequest(req, resp, job)
			if err != nil {
				// Expected error, but we're testing for races
				fmt.Printf("Error: %v\n", err)
			}
		}()
	}
	wg.Wait()

	errorHandler.PrintErrorStats()
}

func TestRequestWorkerPoolRaces(t *testing.T) {
	httpClientOpts := rawhttp.DefaultHTTPClientOptions()
	httpClientOpts.RequestDelay = 100 * time.Millisecond

	// Create worker pool with 30 workers
	pool := rawhttp.NewRequestWorkerPool(httpClientOpts, 30)
	defer pool.Close()

	// Create fake JPEG data (25KB)
	fakeJPEG := make([]byte, 25*1024)
	// JPEG magic bytes header
	fakeJPEG[0] = 0xFF
	fakeJPEG[1] = 0xD8
	fakeJPEG[2] = 0xFF
	fakeJPEG[3] = 0xE0
	// Fill rest with random data
	for i := 4; i < len(fakeJPEG); i++ {
		fakeJPEG[i] = byte(i % 256)
	}
	// JPEG trailer
	fakeJPEG[len(fakeJPEG)-2] = 0xFF
	fakeJPEG[len(fakeJPEG)-1] = 0xD9

	// Create test server that sends chunked response
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Transfer-Encoding", "chunked")
		w.Header().Set("Content-Type", "image/jpeg")

		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("Expected http.Flusher interface")
			return
		}

		// Send data in chunks
		chunkSize := 1024
		for i := 0; i < len(fakeJPEG); i += chunkSize {
			end := i + chunkSize
			if end > len(fakeJPEG) {
				end = len(fakeJPEG)
			}
			w.Write(fakeJPEG[i:end])
			flusher.Flush()
			time.Sleep(100 * time.Millisecond) // Simulate network delay
		}
	}))
	defer ts.Close()

	// Create multiple jobs
	jobs := make([]payload.PayloadJob, 100)
	for i := 0; i < len(jobs); i++ {

		u, _ := rawurlparser.RawURLParse(ts.URL)
		jobs[i] = payload.PayloadJob{
			Scheme:       u.Scheme,
			Host:         u.Host,
			BypassModule: "test",
			PayloadToken: fmt.Sprintf("test-token-%d", i),
			Method:       "GET",
			RawURI:       "/test.jpg",
		}
	}

	// Process jobs concurrently
	var wg sync.WaitGroup
	results := make(chan *rawhttp.RawHTTPResponseDetails, len(jobs))

	for _, job := range jobs {
		wg.Add(1)
		go func(j payload.PayloadJob) {
			defer wg.Done()
			result := pool.ProcessRequestResponseJob(j)
			if result != nil {
				results <- result
			}
		}(job)
	}

	// Wait for all jobs and close results channel
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and verify results
	successCount := 0
	for result := range results {
		if result.StatusCode == http.StatusOK {
			successCount++

			// Verify Content-Type
			if !bytes.Equal(result.ContentType, []byte("image/jpeg")) {
				t.Errorf("Expected content type 'image/jpeg', got '%s'", result.ContentType)
			}

			// Verify JPEG magic bytes in preview
			if len(result.ResponsePreview) >= 4 {
				if result.ResponsePreview[0] != 0xFF || result.ResponsePreview[1] != 0xD8 {
					t.Errorf("Response preview doesn't start with JPEG magic bytes")
				}
			}
		}
	}

	t.Logf("Successful requests: %d/%d", successCount, len(jobs))
	GB403ErrorHandler.GetErrorHandler().PrintErrorStats()
}

func TestMidPathsWorkerPool(t *testing.T) {
	// Configure HTTP client options
	httpClientOpts := rawhttp.DefaultHTTPClientOptions()
	//httpClientOpts.RequestDelay = 0 * time.Millisecond
	httpClientOpts.ResponseBodyPreviewSize = 1024 // 1KB preview
	httpClientOpts.MaxConnsPerHost = 500

	// Create worker pool with 50 workers
	pool := rawhttp.NewRequestWorkerPool(httpClientOpts, 50)
	defer pool.Close()

	// Generate payloads

	// pg := payload.NewPayloadGenerator()
	// targetURL := "http://thumbs-cdn.redtube.com/videos/202401/26/447187221/720P_4000K_447187221.mp4"
	// jobs := pg.GenerateMidPathsJobs(targetURL, "midpaths_test")

	pg := payload.NewPayloadGenerator()
	targetURL := "https://thumbs-cdn.redtube.com/videos/202401/26/447187221/720P_4000K_447187221.mp4"
	jobs := pg.GenerateEndPathsJobs(targetURL, "endpaths_test")

	// Process jobs concurrently
	var wg sync.WaitGroup
	results := make(chan *rawhttp.RawHTTPResponseDetails, len(jobs))

	for _, job := range jobs {
		wg.Add(1)
		go func(j payload.PayloadJob) {
			defer wg.Done()
			result := pool.ProcessRequestResponseJob(j)
			if result != nil {
				results <- result
			}
		}(job)
	}

	// Wait for all jobs and close results channel
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and analyze results
	statusCodes := make(map[int]int)
	for result := range results {
		statusCodes[result.StatusCode]++

		if result.StatusCode > 300 && result.StatusCode < 400 {
			t.Logf("Interesting response found:\nURL: %s\nStatus: %d\nContent-Type: %s\nBody Preview: %s\n",
				result.URL, result.StatusCode, result.ContentType, result.ResponsePreview[:30])
		} else {
			t.Logf("Interesting response found:\nURL: %s\nStatus: %d\nContent-Type: %s\nBody Preview: %s\n",
				result.URL, result.StatusCode, result.ContentType, result.ResponsePreview)
		}
	}

	// Print summary
	t.Logf("Total jobs generated: %d", len(jobs))
	t.Logf("Status code distribution:")
	for code, count := range statusCodes {
		t.Logf("  %d: %d responses", code, count)
	}

	GB403ErrorHandler.GetErrorHandler().PrintErrorStats()
}
