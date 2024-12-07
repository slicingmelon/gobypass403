package experimentaltests

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func executePythonScript(targetURL string) ([]string, error) {
	// Get current working directory
	dir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get working directory: %v", err)
	}

	// Construct absolute path to Python script
	scriptPath := filepath.Join(dir, "gen_midpaths_payloads_py.py")

	// Debug logging
	fmt.Printf("Executing Python script at: %s\n", scriptPath)

	cmd := exec.Command("python", scriptPath, "-u", targetURL)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("failed to execute Python script: %v\nStderr: %s", err, exitErr.Stderr)
		}
		return nil, fmt.Errorf("failed to execute Python script: %v", err)
	}

	var urls []string
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "Total") {
			urls = append(urls, line)
		}
	}

	return urls, nil
}

func TestPayloadGenerationComparison(t *testing.T) {
	targetURL := "http://localhost/test/video.mp4"

	// Get Python-generated URLs
	pythonPayloads, err := executePythonScript(targetURL)
	if err != nil {
		t.Fatalf("Failed to execute Python script: %s", err)
	}

	// Get Go-generated URLs
	goPayloads := t_generateMidPathsJobs(t, targetURL)

	// Convert Go PayloadJobs to comparable URLs
	goURLs := make([]string, 0, len(goPayloads))
	for _, p := range goPayloads {
		// Use BuildAbsoluteURLRaw() to get the full URL
		fullURL := string(p.BuildAbsoluteURLRaw())
		goURLs = append(goURLs, fullURL)
	}

	// Sort both slices for deterministic comparison
	sort.Strings(pythonPayloads)
	sort.Strings(goURLs)

	// Compare counts first
	if len(pythonPayloads) != len(goURLs) {
		t.Fatalf("Payload count mismatch:\nPython (%d):\n%s\n\nGo (%d):\n%s",
			len(pythonPayloads), strings.Join(pythonPayloads, "\n"),
			len(goURLs), strings.Join(goURLs, "\n"))
	}

	// Find differences
	differences := []string{}
	for i := range pythonPayloads {
		if pythonPayloads[i] != goURLs[i] {
			differences = append(differences, fmt.Sprintf(
				"Mismatch at index %d:\nPython: %s\nGo:     %s",
				i, pythonPayloads[i], goURLs[i]))
		}
	}

	if len(differences) > 0 {
		t.Fatalf("Found %d differences:\n%s",
			len(differences), strings.Join(differences, "\n\n"))
	}

	t.Logf("Successfully compared %d payloads - all match!", len(pythonPayloads))
}

// func sendAndVerifyRawRequest(t *testing.T, client *fasthttp.Client, job PayloadJob, stats *TestStats) {
// 	rawReq := bytes.NewBuffer(nil)
// 	rawReq.Write(job.Method)
// 	rawReq.Write([]byte(" "))
// 	rawReq.Write(job.URIPayload)
// 	rawReq.Write([]byte(" HTTP/1.1\r\nHost: "))
// 	rawReq.Write(job.Host)
// 	rawReq.Write([]byte("\r\nX-Debug-Canary: "))
// 	rawReq.Write([]byte(job.Seed))
// 	rawReq.Write([]byte("\r\n\r\n"))

// 	t.Logf("\n%s=== REQUEST [%s] ===%s\n%s",
// 		Yellow, job.Seed, Reset,
// 		rawReq.String())

// 	br := bufio.NewReader(rawReq)
// 	var req fasthttp.Request
// 	if err := req.Read(br); err != nil {
// 		t.Fatalf("unexpected error: %v", err)
// 	}

// 	var resp fasthttp.Response
// 	if err := client.Do(&req, &resp); err != nil {
// 		t.Fatalf("unexpected error: %v", err)
// 	}

// 	stats.mu.Lock()
// 	stats.successfulRequests++
// 	stats.mu.Unlock()
// }

func sendAndVerifyWithInMemoryServer(t *testing.T, job PayloadJob, stats *TestStats) {
	// Create in-memory server
	var wg sync.WaitGroup
	wg.Add(1)

	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	// Create server with handler
	server := &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			canary := ctx.Request.Header.Peek("X-Debug-Canary")

			// Log incoming request
			t.Logf("\n%s=== REQUEST [%s] ===%s\n"+
				"%s> Method: %s\n"+
				"> Host: %s\n"+
				"> URI: %s\n"+
				"> Raw Path: %s%s\n",
				Yellow, canary, Reset,
				Yellow,
				ctx.Method(),
				ctx.Host(),
				ctx.RequestURI(),
				ctx.URI().PathOriginal(), Reset)

			// Set response
			ctx.SetStatusCode(fasthttp.StatusOK)
			ctx.Response.Header.Set("X-Test-Path", string(ctx.URI().PathOriginal()))
			ctx.Response.Header.Set("X-Path-Hash", hashRawPath(ctx.URI().PathOriginal()))

			// Log response
			t.Logf("\n%s=== RESPONSE [%s] ===%s\n"+
				"%s< Status: %d\n"+
				"< Headers: %s\n"+
				"< Path Hash: %s%s\n",
				Blue, canary, Reset,
				Blue,
				ctx.Response.StatusCode(),
				ctx.Response.Header.String(),
				hashRawPath(ctx.URI().PathOriginal()), Reset)
		},
		DisableHeaderNamesNormalizing: true,
	}

	// Start server
	go func() {
		wg.Done()
		if err := server.Serve(ln); err != nil {
			t.Errorf("Server error: %v", err)
		}
	}()

	// Wait for server to start
	wg.Wait()

	// Create client that uses the in-memory listener
	client := &fasthttp.Client{
		Dial: func(addr string) (net.Conn, error) {
			return ln.Dial()
		},
		DisablePathNormalizing:        true,
		DisableHeaderNamesNormalizing: true,
		NoDefaultUserAgentHeader:      true,
		// Keep connections minimal for tests
		MaxConnsPerHost:     1,
		MaxIdleConnDuration: time.Second,
		ReadTimeout:         time.Second * 2,
		WriteTimeout:        time.Second * 2,
	}

	// Use sync.Pool for request/response objects
	reqPool := &sync.Pool{
		New: func() interface{} {
			return &fasthttp.Request{}
		},
	}
	respPool := &sync.Pool{
		New: func() interface{} {
			return &fasthttp.Response{}
		},
	}

	// Get objects from pool
	req := reqPool.Get().(*fasthttp.Request)
	resp := respPool.Get().(*fasthttp.Response)
	defer func() {
		req.Reset()
		resp.Reset()
		reqPool.Put(req)
		respPool.Put(resp)
	}()

	// Construct raw request using bytes.Buffer
	rawReq := bytes.NewBuffer(nil)
	rawReq.Write(job.Method)
	rawReq.Write([]byte(" "))
	rawReq.Write(job.URIPayload)
	rawReq.Write([]byte(" HTTP/1.1\r\nHost: "))
	rawReq.Write(job.Host)
	rawReq.Write([]byte("\r\nX-Debug-Canary: "))
	rawReq.Write([]byte(job.Seed))
	rawReq.Write([]byte("\r\nConnection: close\r\n\r\n"))

	// Log the raw request
	t.Logf("\n%s=== RAW REQUEST [%s] ===%s\n%s",
		Yellow, job.Seed, Reset,
		rawReq.String())

	// Send request
	br := bufio.NewReader(rawReq)
	if err := req.Read(br); err != nil {
		t.Fatalf("Failed to parse raw request: %v", err)
	}

	if err := client.Do(req, resp); err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}

	// Update stats
	stats.mu.Lock()
	stats.successfulRequests++
	stats.mu.Unlock()

	// Cleanup
	client.CloseIdleConnections()
	server.Shutdown()
}

func TestPayloadValidation(t *testing.T) {
	stats := &TestStats{}

	// Generate payloads
	inputURL := "http://localhost/test/video.mp4"
	jobs := t_generateMidPathsJobs(t, inputURL)
	stats.totalPayloads = len(jobs)

	// Process each payload
	for _, job := range jobs {
		sendAndVerifyWithInMemoryServer(t, job, stats)
	}

	// Verify results
	if stats.successfulRequests == 0 {
		t.Error("No successful requests were made")
	}

	t.Logf("Successfully processed %d/%d requests",
		stats.successfulRequests, stats.totalPayloads)
}
