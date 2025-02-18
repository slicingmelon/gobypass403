package tests

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
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

			job := payload.BypassPayload{
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
	jobs := make([]payload.BypassPayload, 100)
	for i := 0; i < len(jobs); i++ {

		u, _ := rawurlparser.RawURLParse(ts.URL)
		jobs[i] = payload.BypassPayload{
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
		go func(j payload.BypassPayload) {
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

	pg := payload.NewPayloadGenerator()
	targetURL := "http://thuxxxxxx1.mp4"
	jobs := pg.GenerateMidPathsPayloads(targetURL, "midpaths_test")

	// Process jobs concurrently
	var wg sync.WaitGroup
	results := make(chan *rawhttp.RawHTTPResponseDetails, len(jobs))

	for _, job := range jobs {
		wg.Add(1)
		go func(j payload.BypassPayload) {
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

func TestEndPathsWorkerPool(t *testing.T) {
	// Configure HTTP client options
	httpClientOpts := rawhttp.DefaultHTTPClientOptions()
	//httpClientOpts.RequestDelay = 0 * time.Millisecond
	httpClientOpts.ResponseBodyPreviewSize = 1024 // 1KB preview

	// Create worker pool with 50 workers
	pool := rawhttp.NewRequestWorkerPool(httpClientOpts, 50)
	defer pool.Close()

	// Generate payloads
	pg := payload.NewPayloadGenerator()
	targetURL := "https://thsssssss221.mp4"
	jobs := pg.GenerateEndPathsPayloads(targetURL, "endpaths_test")

	// Process jobs concurrently
	var wg sync.WaitGroup
	results := make(chan *rawhttp.RawHTTPResponseDetails, len(jobs))

	for _, job := range jobs {
		wg.Add(1)
		go func(j payload.BypassPayload) {
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

func TestFasthttpStreamingConcurrent(t *testing.T) {
	// Create fasthttp client with streaming enabled
	client := &fasthttp.Client{
		MaxConnsPerHost: 500,
		// Enable streaming
		DisableHeaderNamesNormalizing: true,
		DisablePathNormalizing:        true,
		StreamResponseBody:            true,
		MaxResponseBodySize:           12188, // Hardlimit at 12KB
		ReadBufferSize:                13212, // Hardlimit at 13KB
		WriteBufferSize:               13212, // Hardlimit at 13KB
	}

	//workers := 50

	// Generate payloads
	pg := payload.NewPayloadGenerator()
	targetURL := "https://thumbssdasd221.mp4"
	jobs := pg.GenerateEndPathsPayloads(targetURL, "endpaths_test")

	var wg sync.WaitGroup
	results := make(chan struct {
		statusCode int
		err        error
		response   []byte
		url        string // Added to track which URL caused issues
	}, len(jobs)) // Buffer for all jobs

	// Start concurrent requests
	for _, job := range jobs {
		wg.Add(1)
		go func(j payload.BypassPayload) {
			defer wg.Done()

			// Create request
			req := fasthttp.AcquireRequest()
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseRequest(req)
			defer fasthttp.ReleaseResponse(resp)

			fullURL := payload.BypassPayloadToFullURL(j)
			req.SetRequestURI(fullURL)
			req.Header.SetMethod(j.Method) // Use method from job
			req.Header.Set("Connection", "keep-alive")

			err := client.Do(req, resp)
			if err != nil {
				results <- struct {
					statusCode int
					err        error
					response   []byte
					url        string
				}{0, err, nil, fullURL}
				return
			}

			// Read first 1KB of response body
			preview := make([]byte, 1024)
			n, err := resp.BodyStream().Read(preview)
			if err != nil && err != io.EOF {
				results <- struct {
					statusCode int
					err        error
					response   []byte
					url        string
				}{resp.StatusCode(), err, nil, fullURL}
				return
			}

			results <- struct {
				statusCode int
				err        error
				response   []byte
				url        string
			}{resp.StatusCode(), nil, preview[:n], fullURL}
		}(job)
	}

	// Wait and close results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Analyze results
	statusCodes := make(map[int]int)
	errors := make(map[string]int)
	urlErrors := make(map[string][]string) // Track which URLs caused which errors

	for result := range results {
		if result.err != nil {
			errors[result.err.Error()]++
			urlErrors[result.url] = append(urlErrors[result.url], result.err.Error())
			t.Logf("Error for URL %s: %v", result.url, result.err)
			continue
		}

		statusCodes[result.statusCode]++
		if len(result.response) > 0 {
			t.Logf("URL: %s\nStatus: %d\nResponse preview (first 32 bytes): %x",
				result.url,
				result.statusCode,
				result.response[:min(32, len(result.response))])
		}
	}

	// Print summary
	t.Logf("\nTotal jobs: %d", len(jobs))
	t.Logf("\nStatus code distribution:")
	for code, count := range statusCodes {
		t.Logf("  %d: %d responses", code, count)
	}

	if len(errors) > 0 {
		t.Logf("\nErrors distribution:")
		for err, count := range errors {
			t.Logf("  %s: %d occurrences", err, count)
		}

		t.Logf("\nURLs causing errors:")
		for url, errs := range urlErrors {
			t.Logf("  URL: %s", url)
			for _, err := range errs {
				t.Logf("    - %s", err)
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestFasthttpStreamingConcurrent2(t *testing.T) {
	// Create fasthttp client with streaming enabled
	client := &fasthttp.Client{
		MaxConnsPerHost: 500,
		// Enable streaming
		DisableHeaderNamesNormalizing: true,
		DisablePathNormalizing:        true,
		StreamResponseBody:            true,
		MaxResponseBodySize:           12188, // Hardlimit at 12KB
		ReadBufferSize:                13212, // Hardlimit at 13KB
		WriteBufferSize:               13212, // Hardlimit at 13KB
	}

	workers := 50 // Limit concurrent workers

	// Generate payloads
	pg := payload.NewPayloadGenerator()
	targetURL := "https://thumbsfdsfsd221.mp4"
	jobs := pg.GenerateEndPathsPayloads(targetURL, "endpaths_test")

	// Create job and result channels
	jobsChan := make(chan payload.BypassPayload, len(jobs))
	results := make(chan struct {
		statusCode int
		err        error
		response   []byte
		url        string
	}, len(jobs))

	// Start worker pool
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobsChan {
				// Create request
				req := fasthttp.AcquireRequest()
				resp := fasthttp.AcquireResponse()
				defer fasthttp.ReleaseRequest(req)
				defer fasthttp.ReleaseResponse(resp)

				fullURL := payload.BypassPayloadToFullURL(job)
				req.SetRequestURI(fullURL)
				req.Header.SetMethod(job.Method)
				req.Header.Set("Connection", "keep-alive")

				err := client.Do(req, resp)
				if err != nil {
					results <- struct {
						statusCode int
						err        error
						response   []byte
						url        string
					}{0, err, nil, fullURL}
					continue
				}

				// Read first 1KB of response body
				preview := make([]byte, 1024)
				n, err := resp.BodyStream().Read(preview)
				if err != nil && err != io.EOF {
					results <- struct {
						statusCode int
						err        error
						response   []byte
						url        string
					}{resp.StatusCode(), err, nil, fullURL}
					continue
				}

				results <- struct {
					statusCode int
					err        error
					response   []byte
					url        string
				}{resp.StatusCode(), nil, preview[:n], fullURL}
			}
		}()
	}

	// Feed jobs to workers
	go func() {
		for _, job := range jobs {
			jobsChan <- job
		}
		close(jobsChan)
	}()

	// Wait for all workers to finish and close results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Analyze results
	statusCodes := make(map[int]int)
	errors := make(map[string]int)
	urlErrors := make(map[string][]string)

	for result := range results {
		if result.err != nil {
			errors[result.err.Error()]++
			urlErrors[result.url] = append(urlErrors[result.url], result.err.Error())
			t.Logf("Error for URL %s: %v", result.url, result.err)
			continue
		}

		statusCodes[result.statusCode]++
		if len(result.response) > 0 {
			t.Logf("URL: %s\nStatus: %d\nResponse preview (first 32 bytes): %x",
				result.url,
				result.statusCode,
				result.response[:min(32, len(result.response))])
		}
	}

	// Print summary
	t.Logf("\nTotal jobs: %d", len(jobs))
	t.Logf("Workers used: %d", workers)
	t.Logf("\nStatus code distribution:")
	for code, count := range statusCodes {
		t.Logf("  %d: %d responses", code, count)
	}

	if len(errors) > 0 {
		t.Logf("\nErrors distribution:")
		for err, count := range errors {
			t.Logf("  %s: %d occurrences", err, count)
		}

		t.Logf("\nURLs causing errors:")
		for url, errs := range urlErrors {
			t.Logf("  URL: %s", url)
			for _, err := range errs {
				t.Logf("    - %s", err)
			}
		}
	}
}

func createCustomDialer() fasthttp.DialFunc {
	return func(addr string) (net.Conn, error) {
		dialer := &fasthttp.TCPDialer{
			Concurrency:      500,
			DNSCacheDuration: time.Minute,
		}

		// Create error context
		errorContext := GB403ErrorHandler.ErrorContext{
			ErrorSource: []byte("TestFasthttpStreamingConcurrent3.Dial"),
			Host:        []byte(addr),
		}

		conn, err := dialer.DialDualStack(addr)
		if err != nil {
			if handleErr := GB403ErrorHandler.GetErrorHandler().HandleError(err, errorContext); handleErr != nil {
				return nil, fmt.Errorf("dial error handling failed: %v (original error: %v)", handleErr, err)
			}
			return nil, err
		}
		return conn, nil
	}
}

func TestFasthttpStreamingConcurrent3(t *testing.T) {
	// Create fasthttp client with streaming enabled
	client := &fasthttp.Client{
		MaxConnsPerHost:               500,
		DisableHeaderNamesNormalizing: true,
		DisablePathNormalizing:        true,
		StreamResponseBody:            true,
		MaxResponseBodySize:           12188,
		ReadBufferSize:                13212,
		WriteBufferSize:               13212,
		Dial:                          createCustomDialer(),
	}

	workers := 50
	errHandler := GB403ErrorHandler.GetErrorHandler()

	// Generate payloads
	pg := payload.NewPayloadGenerator()
	targetURL := "https://txxxxxxxx0Kssss7221.mp4"
	jobs := pg.GenerateEndPathsPayloads(targetURL, "endpaths_test")

	jobsChan := make(chan payload.BypassPayload, len(jobs))
	results := make(chan struct {
		statusCode int
		err        error
		response   []byte
		url        string
	}, len(jobs))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobsChan {
				req := fasthttp.AcquireRequest()
				resp := fasthttp.AcquireResponse()
				defer fasthttp.ReleaseRequest(req)
				defer fasthttp.ReleaseResponse(resp)

				fullURL := payload.BypassPayloadToFullURL(job)
				req.SetRequestURI(fullURL)
				req.Header.SetMethod(job.Method)
				req.Header.Set("Connection", "keep-alive")

				err := client.DoTimeout(req, resp, 5*time.Second)
				if err != nil {
					// Create error context
					errorContext := GB403ErrorHandler.ErrorContext{
						ErrorSource:  []byte("TestFasthttpStreamingConcurrent3"),
						Host:         []byte(payload.BypassPayloadToFullURL(job)),
						BypassModule: []byte(job.BypassModule),
						DebugToken:   []byte(job.PayloadToken),
					}
					errHandler.HandleError(err, errorContext)

					results <- struct {
						statusCode int
						err        error
						response   []byte
						url        string
					}{0, err, nil, fullURL}
					continue
				}

				preview := make([]byte, 1024)
				n, err := resp.BodyStream().Read(preview)
				if err != nil && err != io.EOF {
					// Create error context for body read errors
					errorContext := GB403ErrorHandler.ErrorContext{
						ErrorSource:  []byte("TestFasthttpStreamingConcurrent2.BodyRead"),
						Host:         []byte(job.Scheme + "://" + job.Host),
						BypassModule: []byte(job.BypassModule),
						DebugToken:   []byte(job.PayloadToken),
					}
					errHandler.HandleError(err, errorContext)

					results <- struct {
						statusCode int
						err        error
						response   []byte
						url        string
					}{resp.StatusCode(), err, nil, fullURL}
					continue
				}

				results <- struct {
					statusCode int
					err        error
					response   []byte
					url        string
				}{resp.StatusCode(), nil, preview[:n], fullURL}
			}
		}()
	}

	go func() {
		for _, job := range jobs {
			jobsChan <- job
		}
		close(jobsChan)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	statusCodes := make(map[int]int)
	errors := make(map[string]int)
	urlErrors := make(map[string][]string)

	for result := range results {
		if result.err != nil {
			errors[result.err.Error()]++
			urlErrors[result.url] = append(urlErrors[result.url], result.err.Error())
			t.Logf("Error for URL %s: %v", result.url, result.err)
			continue
		}

		statusCodes[result.statusCode]++
		if len(result.response) > 0 {
			t.Logf("URL: %s\nStatus: %d\nResponse preview (first 32 bytes): %x",
				result.url,
				result.statusCode,
				result.response[:min(32, len(result.response))])
		}
	}

	// Print summary
	t.Logf("\nTotal jobs: %d", len(jobs))
	t.Logf("Workers used: %d", workers)
	t.Logf("\nStatus code distribution:")
	for code, count := range statusCodes {
		t.Logf("  %d: %d responses", code, count)
	}

	if len(errors) > 0 {
		t.Logf("\nErrors distribution:")
		for err, count := range errors {
			t.Logf("  %s: %d occurrences", err, count)
		}

		t.Logf("\nURLs causing errors:")
		for url, errs := range urlErrors {
			t.Logf("  URL: %s", url)
			for _, err := range errs {
				t.Logf("    - %s", err)
			}
		}
	}

	// Print error handler stats at the end
	errHandler.PrintErrorStats()
}
