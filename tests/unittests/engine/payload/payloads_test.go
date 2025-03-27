package tests

import (
	"testing"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
)

func TestGenerateHeaderIPJobs_RequestFormat(t *testing.T) {
	targetURL := "https://www.example.com/admin"
	bypassModule := "header_ip"

	// Create PayloadGenerator instance
	pg := payload.NewPayloadGenerator()

	// Generate sample jobs
	jobs := pg.GenerateHeaderIPPayloads(targetURL, bypassModule, "", "")

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
	pg := payload.NewPayloadGenerator()

	// Generate all jobs
	jobs := pg.GenerateHeaderIPPayloads(targetURL, bypassModule, "", "")

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
