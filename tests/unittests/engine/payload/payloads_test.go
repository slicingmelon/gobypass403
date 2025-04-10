package tests

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
	"github.com/slicingmelon/gobypass403/core/engine/rawhttp"
	"github.com/valyala/fasthttp"
)

func TestGenerateHeaderIPJobs_RequestFormat(t *testing.T) {
	targetURL := "https://www.example.com/admin"
	bypassModule := "header_ip"

	// Create PayloadGenerator instance
	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: bypassModule,
	})

	// Generate sample jobs
	jobs := pg.GenerateHeadersIPPayloads(targetURL, bypassModule)

	// Print a few sample jobs to demonstrate the structure
	t.Log("\nSample PayloadJobs generated for:", targetURL)

	// Print the special case job (first job)
	specialJob := jobs[0]
	t.Logf("\nSpecial Case Job (X-AppEngine-Trusted-IP):")
	t.Logf("Raw HTTP Request would look like:\n"+
		"GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"%s: %s\r\n"+
		"\r\n",
		specialJob.RawURI,
		specialJob.Host,
		specialJob.Headers[0].Header,
		specialJob.Headers[0].Value,
	)

	// Print a few regular jobs
	for i, job := range jobs[1:4] { // Just show first 3 regular jobs
		t.Logf("\nSample Job #%d:", i+1)
		t.Logf("PayloadJob struct:")
		t.Logf("  OriginalURL: %s", job.OriginalURL)
		t.Logf("  Method: %s", job.Method)
		t.Logf("  Host: %s", job.Host)
		t.Logf("  RawURI: %s", job.RawURI)
		t.Logf("  BypassModule: %s", job.BypassModule)
		t.Logf("  FullURL: %s", payload.BypassPayloadToFullURL(job))
		t.Logf("  Headers:")
		for _, h := range job.Headers {
			t.Logf("    %s: %s", h.Header, h.Value)
		}

		// Show how the actual HTTP request would look
		t.Logf("\nRaw HTTP Request would look like:\n"+
			"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"%s: %s\r\n"+
			"\r\n",
			job.RawURI,
			job.Host,
			job.Headers[0].Header,
			job.Headers[0].Value,
		)
	}

	// Print some statistics
	headerTypes := make(map[string]int)
	for _, job := range jobs {
		for _, header := range job.Headers {
			headerTypes[header.Header]++
		}
	}

	t.Logf("\nStatistics:")
	t.Logf("Total jobs generated: %d", len(jobs))
	t.Logf("Header types and counts:")
	for header, count := range headerTypes {
		t.Logf("  %s: %d jobs", header, count)
	}
}

func TestGenerateHeaderIPJobs_RequestFormatAllJobs(t *testing.T) {
	targetURL := "https://www.example.com/admin"
	bypassModule := "header_ip"

	// Create PayloadGenerator instance
	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    targetURL,
		BypassModule: bypassModule,
	})

	// Generate all jobs
	jobs := pg.GenerateHeadersIPPayloads(targetURL, bypassModule)

	t.Logf("\nAll PayloadJobs generated for: %s", targetURL)
	t.Logf("Total jobs generated: %d\n", len(jobs))

	// Print all jobs
	for i, job := range jobs {
		t.Logf("\nJob #%d:", i+1)

		// Print the PayloadJob struct details
		t.Logf("PayloadJob struct:")
		t.Logf("  OriginalURL: %s", job.OriginalURL)
		t.Logf("  Method: %s", job.Method)
		t.Logf("  Host: %s", job.Host)
		t.Logf("  RawURI: %s", job.RawURI)
		t.Logf("  BypassModule: %s", job.BypassModule)
		t.Logf("  FullURL: %s", payload.BypassPayloadToFullURL(job))
		t.Logf("  Headers:")
		for _, h := range job.Headers {
			t.Logf("    %s: %s", h.Header, h.Value)
		}

		// Show how the actual HTTP request would look
		t.Logf("\nRaw HTTP Request would look like:\n"+
			"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"%s: %s\r\n"+
			"\r\n",
			job.RawURI,
			job.Host,
			job.Headers[0].Header,
			job.Headers[0].Value,
		)
		t.Logf("----------------------------------------")
	}

	// Print statistics at the end
	headerTypes := make(map[string]int)
	for _, job := range jobs {
		for _, header := range job.Headers {
			headerTypes[header.Header]++
		}
	}

	t.Logf("\nStatistics:")
	t.Logf("Total jobs generated: %d", len(jobs))
	t.Logf("Header types and counts:")
	for header, count := range headerTypes {
		t.Logf("  %s: %d jobs", header, count)
	}
}

func TestPayloadSeedRoundTrip(t *testing.T) {
	// Test case matching your HeaderIP job
	original := payload.BypassPayload{
		Scheme: "https",
		Host:   "www.example.com",
		RawURI: "/admin",
		Headers: []payload.Headers{{
			Header: "X-AppEngine-Trusted-IP-Request",
			Value:  "1",
		}},
	}

	// Generate seed
	seed := "ywHwygH_BCkBgFkEAQgGAQYBBWh0dHBzAjJzdGFnZTktcHJvYmlsbGVyLW1pbGVoaWdobWVkaWEucHJvamVjdDFzZXJ2aWNlLmNvbQNeLzBkMy9kYzQvNTk4L2IyZS80NGIvNGE1LzMzNS9iZWIvZjM3L2VhNS85NS92aWRlby9mZTBjZDhiZTA0M2I1NWQ1ZTRlYjA1YjIzMmU0Mzc4NGFiZGYyOTMyLm1wNAQDR0VUBQEQWC1UcnVlLUNsaWVudC1JUApub3JlYWxob3N0"
	t.Logf("Generated seed: %s", seed)
	// Recover data
	recovered, err := payload.DecodePayloadToken(seed)

	if err != nil {
		t.Fatalf("Failed to recover seed: %v", err)
	}
	// Compare
	t.Logf("Original URL: %s, Recovered URL: %s", original.Scheme+"://"+original.Host+original.RawURI, recovered.Scheme+"://"+recovered.Host+recovered.RawURI)
	t.Logf("Original Headers: %+v", original.Headers)
	t.Logf("Recovered Headers: %+v", recovered.Headers)
	if original.Scheme+"://"+original.Host+original.RawURI != recovered.Scheme+"://"+recovered.Host+recovered.RawURI {
		t.Errorf("URLs don't match")
	}
	if len(original.Headers) != len(recovered.Headers) {
		t.Errorf("Header count mismatch: %d != %d", len(original.Headers), len(recovered.Headers))
	}
	for i, h := range original.Headers {
		if recovered.Headers[i].Header != h.Header || recovered.Headers[i].Value != h.Value {
			t.Errorf("Header %d mismatch: %+v != %+v", i, h, recovered.Headers[i])
		}
	}
}

func TestNginxACLsBypassPayloadsRawURI(t *testing.T) {
	// Create a PayloadGenerator
	pg := payload.NewPayloadGenerator(payload.PayloadGeneratorOptions{
		TargetURL:    "http://localhost/admin",
		BypassModule: "nginx_bypasses-test",
	})

	// Generate the payloads
	payloads := pg.GenerateNginxACLsBypassPayloads("http://localhost/admin", "nginx_bypasses-test")
	if len(payloads) == 0 {
		t.Fatalf("No payloads were generated")
	}

	t.Logf("Generated %d payloads to test", len(payloads))

	// Create HTTP client
	httpClient := rawhttp.NewHTTPClient(rawhttp.DefaultHTTPClientOptions())

	// Track failures
	var failCount int
	var failMu sync.Mutex

	// Test each payload
	for i, bypassPayload := range payloads { // Test all payloads
		t.Run(fmt.Sprintf("Payload_%d", i), func(t *testing.T) {
			// Create a new request and response for each payload
			req := fasthttp.AcquireRequest()
			defer fasthttp.ReleaseRequest(req)
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseResponse(resp)

			// Build the raw HTTP request
			err := rawhttp.BuildRawHTTPRequest(httpClient, req, bypassPayload)
			if err != nil {
				t.Fatalf("Failed to build raw HTTP request: %v", err)
			}

			// Log the request details
			t.Logf("Testing payload %d", i)
			t.Logf("RawURI: %s", bypassPayload.RawURI)
			t.Logf("Method: %s", bypassPayload.Method)
			t.Logf("Request before sending: %s", req.String())

			// Send request to the echo server
			_, err = httpClient.DoRequest(req, resp, bypassPayload)
			if err != nil {
				failMu.Lock()
				failCount++
				failMu.Unlock()
				t.Fatalf("Failed to send request: %v", err)
			}

			// Get the response body which should contain the exact request sent
			responseBody := resp.Body()

			// Split the response to get the first line (request line)
			lines := strings.Split(string(responseBody), "\n")
			if len(lines) == 0 {
				failMu.Lock()
				failCount++
				failMu.Unlock()
				t.Fatalf("Empty response from echo server")
			}

			firstLine := strings.TrimSpace(lines[0])
			t.Logf("First line of response: %s", firstLine)

			// Check if the raw URI was preserved correctly
			expectedRequestLine := fmt.Sprintf("%s %s HTTP/1.1", bypassPayload.Method, bypassPayload.RawURI)
			if !strings.HasPrefix(firstLine, expectedRequestLine) {
				failMu.Lock()
				failCount++
				failMu.Unlock()
				t.Errorf("Raw request line not correctly preserved. Got: '%s', Want: '%s'", firstLine, expectedRequestLine)
			} else {
				t.Logf("Raw request line matched successfully")
			}
		})
	}

	// Print summary
	if failCount > 0 {
		t.Logf("TEST SUMMARY: %d out of %d tests failed", failCount, len(payloads))
	} else {
		t.Logf("TEST SUMMARY: All %d tests passed successfully", len(payloads))
	}
}
