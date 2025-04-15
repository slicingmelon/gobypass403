package payload

import (
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

/*
GenerateEndPathsPayloads generates payloads by appending suffixes from
internal_endpaths.lst to the base path.

It creates variants with and without a trailing slash for each suffix.
If the base path is not "/", it also creates variants where the suffix
is directly appended without a preceding slash (if the suffix doesn't start
with a letter).

If any generated path segment (before appending the original query) contains
literal '?' or '#' characters, additional payloads are generated where these
special characters are percent-encoded (%3F and %23) to ensure the original
query string can be appended unambiguously.
*/
func (pg *PayloadGenerator) GenerateEndPathsPayloads(targetURL string, bypassModule string) []BypassPayload {
	var jobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL: %s", targetURL)
		return jobs
	}

	payloads, err := ReadPayloadsFromFile("internal_endpaths.lst") // Assumes this reads from the correct location (local or embedded)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read endpaths payloads: %v", err)
		return jobs
	}

	basePath := parsedURL.Path // Path might contain raw '?' or '#'
	separator := ""
	// Add separator only if basePath is not just "/" and doesn't already end with "/"
	if basePath != "/" && !strings.HasSuffix(basePath, "/") {
		separator = "/"
	}

	query := ""
	// Use Query, not RawQuery as noted
	if parsedURL.Query != "" {
		query = "?" + parsedURL.Query
	}

	// Using map to automatically handle deduplication of final RawURIs
	uniquePaths := make(map[string]struct{})

	// Helper to add path and its special-char-encoded variant if necessary
	addPathVariants := func(pathCandidate string) {
		// Add the standard variant
		uniquePaths[pathCandidate+query] = struct{}{}

		// Check if the path part contains special chars before query is appended
		if strings.ContainsAny(pathCandidate, "?#") {
			encodedPath := encodeQueryAndFragmentChars(pathCandidate)
			uniquePaths[encodedPath+query] = struct{}{} // Add special char encoded variant
		}
	}

	for _, payload := range payloads {
		// Variant 1: url/suffix
		pathVariant1 := basePath + separator + payload
		addPathVariants(pathVariant1)

		// Variant 2: url/suffix/
		pathVariant2 := basePath + separator + payload + "/"
		addPathVariants(pathVariant2)

		// Variants 3 & 4 only if basePath is not "/" AND payload doesn't start with a letter
		// (avoids things like /admin/login -> /adminlogin if payload is "login")
		if basePath != "/" && len(payload) > 0 && !isLetter(payload[0]) {
			// Variant 3: url suffix (no separator)
			pathVariant3 := basePath + payload
			addPathVariants(pathVariant3)

			// Variant 4: url suffix / (no separator)
			pathVariant4 := basePath + payload + "/"
			addPathVariants(pathVariant4)
		}
	}

	// Create final jobs from the deduplicated map
	for rawURI := range uniquePaths {
		job := BypassPayload{
			OriginalURL:  targetURL,
			Method:       "GET", // Consider making method configurable or based on input
			Scheme:       parsedURL.Scheme,
			Host:         parsedURL.Host,
			RawURI:       rawURI, // rawURI includes the correctly appended query
			BypassModule: bypassModule,
		}
		job.PayloadToken = GeneratePayloadToken(job)
		jobs = append(jobs, job)
	}

	// Log the total number of unique jobs created for this module
	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s", len(jobs), targetURL)
	return jobs
}
