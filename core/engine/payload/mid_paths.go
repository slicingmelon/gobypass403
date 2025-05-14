package payload

import (
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

/*
GenerateMidPathsPayloads generates payloads by inserting mid-path segments from
internal_midpaths.lst around path segments.

For each slash position in the path, it creates these variants:
1. After-slash insertion:
  - Replace Nth "/" with "/PAYLOAD" (e.g., /a/b -> /a/PAYLOAD/b)

2. Before-slash insertion:
  - Replace Nth "/" with "PAYLOAD/" (e.g., /a/b -> /aPAYLOAD/b)

3. After-path insertion:
  - Add payload after the last path segment (e.g., /a/b -> /a/bPAYLOAD)

Each variant is generated both as-is and with an extra leading slash.
If a path segment contains ? or # characters, an additional variant with
those characters percent-encoded is generated.
*/
func (pg *PayloadGenerator) GenerateMidPathsPayloads(targetURL string, bypassModule string) []BypassPayload {
	var jobs []BypassPayload
	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL: %s", targetURL)
		return jobs
	}

	payloads, err := ReadPayloadsFromFile("internal_midpaths.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read midpaths payloads: %v", err)
		return jobs
	}

	// Get the path, ensuring it starts with a slash
	path := parsedURL.Path
	if path == "" {
		path = "/"
	}

	// Handle query string
	query := ""
	if parsedURL.Query != "" {
		query = "?" + parsedURL.Query
	}

	// Map to store unique paths (for deduplication)
	uniquePaths := make(map[string]struct{})

	// Helper function to add paths with proper handling of special characters
	addPathWithVariants := func(path string) {
		// Add path as-is
		uniquePaths[path+query] = struct{}{}

		// Add path with encoded special characters if needed
		if strings.ContainsAny(path, "?#") {
			encodedPath := encodeQueryAndFragmentChars(path)
			uniquePaths[encodedPath+query] = struct{}{}
		}
	}

	slashCount := strings.Count(path, "/")

	// Handle paths that don't start with a slash by temporarily adding one
	hasLeadingSlash := strings.HasPrefix(path, "/")
	effectivePath := path
	if !hasLeadingSlash && path != "" {
		effectivePath = "/" + path
		slashCount++
	}

	// For each position in the path
	for i := 1; i <= slashCount; i++ {
		for _, payload := range payloads {
			// 1. After-slash insertion: /admin/login -> /admin/payload/login
			afterSlash := ReplaceNth(effectivePath, "/", "/"+payload, i)

			// Fix path if we added a temporary leading slash
			if !hasLeadingSlash && strings.HasPrefix(afterSlash, "/") {
				afterSlash = strings.TrimPrefix(afterSlash, "/")
			}

			// Add both with and without extra leading slash
			addPathWithVariants(afterSlash)
			addPathWithVariants("/" + afterSlash)

			// 2. Before-slash insertion: /admin/login -> /adminpayload/login
			// Skip first slash to match Python behavior
			if i > 1 || !hasLeadingSlash {
				beforeSlash := ReplaceNth(effectivePath, "/", payload+"/", i)

				// Fix path if we added a temporary leading slash
				if !hasLeadingSlash && strings.HasPrefix(beforeSlash, "/") {
					beforeSlash = strings.TrimPrefix(beforeSlash, "/")
				}

				// Add both with and without extra leading slash
				addPathWithVariants(beforeSlash)
				addPathWithVariants("/" + beforeSlash)
			}
		}
	}

	// 3. After-path insertion: /admin/login -> /admin/loginpayload
	if path != "/" && path != "" {
		for _, payload := range payloads {
			// Add payload to the end of the path
			afterPath := path + payload

			// Add both with and without extra leading slash
			addPathWithVariants(afterPath)
			addPathWithVariants("/" + strings.TrimPrefix(afterPath, "/"))
		}
	}

	// Convert unique paths to BypassPayload jobs
	for rawURI := range uniquePaths {
		// Skip if it's just the query
		if rawURI == query && query != "" {
			continue
		}

		// Ensure path starts with / if the original did
		finalURI := rawURI
		if hasLeadingSlash && !strings.HasPrefix(finalURI, "/") && !strings.HasPrefix(finalURI, "?") {
			finalURI = "/" + finalURI
		}

		// DO NOT normalize double slashes - they're important for bypass techniques
		// This was: finalURI = strings.ReplaceAll(finalURI, "//", "/")

		job := BypassPayload{
			OriginalURL:  targetURL,
			Method:       "GET",
			Scheme:       parsedURL.Scheme,
			Host:         parsedURL.Host,
			RawURI:       finalURI,
			BypassModule: bypassModule,
		}
		job.PayloadToken = GeneratePayloadToken(job)
		jobs = append(jobs, job)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s", len(jobs), targetURL)
	return jobs
}
