package payload

import (
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

/*
GenerateMidPathsPayloads generates payloads by inserting segments from
internal_midpaths.lst at various positions in URLs.

For a URL like /a/b, it creates these variants:
1. Before path:
  - PAYLOAD/a/b
  - /PAYLOAD/a/b

2. At each segment:
  - /PAYLOADa/b (fused with first segment start)
  - /aPAYLOAD/b (fused with first segment end)
  - /a/PAYLOADb (fused with second segment start)
  - /a/bPAYLOAD (fused with second segment end)

3. After each slash:
  - /a/PAYLOAD/b (inserted after a slash)

Each variant is generated both as-is and with path normalization variants.
If a path segment contains ? or # characters, additional variants with
those characters percent-encoded are generated.
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

	// Get the path, ensuring it starts with a slash for processing
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

	// Split path into segments for insertion
	hasLeadingSlash := strings.HasPrefix(path, "/")
	pathWithoutLeadingSlash := strings.TrimPrefix(path, "/")
	segments := strings.Split(pathWithoutLeadingSlash, "/")

	// 1. Variants before the entire path
	for _, payload := range payloads {
		// Before path without leading slash: PAYLOAD/a/b
		addPathWithVariants(payload + path)

		// Before path with leading slash: /PAYLOAD/a/b
		addPathWithVariants("/" + payload + path)

		// Special case - preserve double slashes if payload ends with slash: /PAYLOAD//a/b
		if strings.HasSuffix(payload, "/") && hasLeadingSlash {
			addPathWithVariants("/" + payload + path) // This keeps the double slash
		}
	}

	// Skip segment manipulations if path is just "/"
	if path != "/" {
		// 2. Process each segment
		for i, segment := range segments {
			if segment == "" {
				continue // Skip empty segments
			}

			for _, payload := range payloads {
				// Create path prefix up to current segment
				prefix := ""
				if hasLeadingSlash {
					prefix = "/"
				}
				for j := 0; j < i; j++ {
					if segments[j] != "" {
						prefix += segments[j] + "/"
					}
				}

				// Create path suffix after current segment
				suffix := ""
				for j := i + 1; j < len(segments); j++ {
					if segments[j] != "" {
						suffix += "/" + segments[j]
					}
				}

				// Variants at segment:

				// Payload fused with segment start: /PAYLOADsegment/
				segStartFused := prefix + payload + segment + suffix
				addPathWithVariants(segStartFused)
				addPathWithVariants("/" + strings.TrimPrefix(segStartFused, "/"))

				// Payload fused with segment end: /segmentPAYLOAD/
				segEndFused := prefix + segment + payload + suffix
				addPathWithVariants(segEndFused)
				addPathWithVariants("/" + strings.TrimPrefix(segEndFused, "/"))

				// Payload after slash before segment: /segment/PAYLOAD/next
				if i < len(segments)-1 || suffix == "" {
					afterSlash := prefix + segment + "/" + payload + suffix
					addPathWithVariants(afterSlash)
					addPathWithVariants("/" + strings.TrimPrefix(afterSlash, "/"))
				}
			}
		}
	}

	// Convert unique paths to BypassPayload jobs
	for rawURI := range uniquePaths {
		// Skip if it's just the query
		if rawURI == query && query != "" {
			continue
		}

		// DO NOT normalize double slashes - they're important for bypass techniques

		job := BypassPayload{
			OriginalURL:  targetURL,
			Method:       "GET",
			Scheme:       parsedURL.Scheme,
			Host:         parsedURL.Host,
			RawURI:       rawURI,
			BypassModule: bypassModule,
		}
		job.PayloadToken = GeneratePayloadToken(job)
		jobs = append(jobs, job)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s", len(jobs), targetURL)
	return jobs
}
