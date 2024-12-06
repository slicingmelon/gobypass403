package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/valyala/fasthttp"
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

func TestPayloadValidation(t *testing.T) {
	stats := &TestStats{}

	// Generate payloads
	inputURL := "http://localhost/test/video.mp4"
	jobs := t_generateMidPathsJobs(t, inputURL)
	stats.totalPayloads = len(jobs)

	// Create fasthttp client
	client := &fasthttp.Client{
		DisablePathNormalizing:        true,
		DisableHeaderNamesNormalizing: true,
		NoDefaultUserAgentHeader:      true,
	}

	// Process each payload
	for _, job := range jobs {
		sendAndVerifyRawRequest(t, client, job, stats)
	}

	// Verify results
	if stats.successfulRequests == 0 {
		t.Error("No successful requests were made")
	}

	t.Logf("Successfully processed %d/%d requests",
		stats.successfulRequests, stats.totalPayloads)
}
