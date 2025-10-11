package payload

import (
	"strings"
	"unicode/utf8"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

const (
	// maxNormalizationsExperimental limits the number of Unicode lookalike variants
	// generated per character position to control payload explosion
	maxNormalizationsExperimental = 5
)

// substituteAtPosition replaces the character at a specific position with a Unicode lookalike.
// Returns the modified payload and whether a substitution was made.
func substituteAtPosition(payload string, charMap map[rune][]string, targetPos int, mappingIndex int) (string, bool) {
	input := []byte(payload)
	var builder strings.Builder
	builder.Grow(len(input) * 3) // Pre-allocate for potential UTF-8 expansion

	modified := false
	currentPos := 0 // Tracks substitutable position (ignores percent-encoded sequences)

	for i := 0; i < len(input); {
		// Check for percent-encoding (byte-based, more efficient)
		if input[i] == '%' && i+2 < len(input) &&
			isHexDigitASCII(input[i+1]) && isHexDigitASCII(input[i+2]) {
			// Keep percent-encoded sequences as-is (don't count as substitutable position)
			builder.Write(input[i : i+3])
			i += 3
			continue
		}

		// Decode UTF-8 rune properly
		r, size := utf8.DecodeRune(input[i:])

		// Check if this is the target position for substitution
		if currentPos == targetPos {
			if lookalikes, ok := charMap[r]; ok && mappingIndex < len(lookalikes) {
				builder.WriteString(lookalikes[mappingIndex])
				modified = true
				i += size
				currentPos++
				continue
			}
		}

		// No substitution - encode the rune back using utf8.EncodeRune
		var buf [4]byte
		n := utf8.EncodeRune(buf[:], r)
		builder.Write(buf[:n])

		i += size
		currentPos++
	}

	return builder.String(), modified
}

/*
GenerateUnicodePathExperimentalPayloads generates payloads by systematically substituting characters
in the mid_paths list with their Unicode lookalikes, one position at a time.

This module generates multiple variants per payload by:
 1. Finding all substitutable character positions (excluding percent-encoded sequences)
 2. For each position, generating up to maxNormalizationsExperimental variants
 3. Each variant substitutes ONE character at ONE position with a Unicode lookalike

This approach maximizes bypass discovery chances by testing different combinations.

Example for payload "..;":
  - Position 0: "․.;" (first dot → U+2024), "﹒.;" (first dot → U+FE52)
  - Position 1: ".․;" (second dot → U+2024), ".﹒;" (second dot → U+FE52)
  - Position 2: "..︔" (semicolon → U+FE54), "..﹔" (semicolon → U+FE54)
*/
func (pg *PayloadGenerator) GenerateUnicodePathExperimentalPayloads(targetURL string, bypassModule string) []BypassPayload {
	// 1. Load the Unicode character map for substitutions
	unicodeMap, err := ReadUnicodeCharMap()
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read unicode_char_map.json for experimental module: %v", err)
		return []BypassPayload{}
	}

	// 2. Build lookup map: rune -> []string (all available lookalikes, excluding the ASCII itself)
	charToLookalikes := make(map[rune][]string)
	for _, entry := range unicodeMap {
		if len(entry.Char) > 0 && len(entry.Mappings) >= 2 {
			charRunes := []rune(entry.Char)
			if len(charRunes) > 0 {
				// Store all mappings EXCEPT the first one (which is the ASCII character itself)
				lookalikes := make([]string, 0, len(entry.Mappings)-1)
				for i := 1; i < len(entry.Mappings); i++ {
					lookalikes = append(lookalikes, entry.Mappings[i].Unicode)
				}
				if len(lookalikes) > 0 {
					charToLookalikes[charRunes[0]] = lookalikes
				}
			}
		}
	}

	// 3. Read the raw midpath payloads from the file
	rawPayloads, err := ReadPayloadsFromFile("internal_midpaths.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read midpaths payloads for experimental module: %v", err)
		return []BypassPayload{}
	}

	// 4. Generate Unicode variants by systematic substitution
	unicodePayloadsSet := make(map[string]struct{}) // Use map for deduplication
	totalVariantsGenerated := 0

	for _, payload := range rawPayloads {
		// Count substitutable positions (excluding percent-encoded sequences)
		substitutablePositions := countSubstitutablePositions(payload, charToLookalikes)

		if substitutablePositions == 0 {
			continue // Skip payloads with no substitutable characters
		}

		// Generate variants by substituting ONE position at a time
		for pos := 0; pos < substitutablePositions; pos++ {
			// Generate up to maxNormalizationsExperimental variants for this position
			variantsAtPosition := 0
			for mappingIdx := 0; mappingIdx < maxNormalizationsExperimental; mappingIdx++ {
				variant, modified := substituteAtPosition(payload, charToLookalikes, pos, mappingIdx)

				if modified && variant != payload {
					// Only add if it's different from original and actually modified
					if _, exists := unicodePayloadsSet[variant]; !exists {
						unicodePayloadsSet[variant] = struct{}{}
						totalVariantsGenerated++
						variantsAtPosition++
					}
				} else {
					// No more valid mappings for this position
					break
				}
			}
		}
	}

	// Convert set to slice
	unicodePayloads := make([]string, 0, len(unicodePayloadsSet))
	for payload := range unicodePayloadsSet {
		unicodePayloads = append(unicodePayloads, payload)
	}

	// If no payloads were generated, return empty
	if len(unicodePayloads) == 0 {
		GB403Logger.Debug().BypassModule(bypassModule).Msgf(
			"No Unicode variants generated (checked %d payloads, 0 modified)",
			len(rawPayloads),
		)
		return []BypassPayload{}
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf(
		"Generated %d unique Unicode variants from %d base payloads (before URL encoding)",
		len(unicodePayloads), len(rawPayloads),
	)

	// 5. Double the payloads: add URL-encoded versions of each Unicode variant
	finalPayloads := make([]string, 0, len(unicodePayloads)*2)
	for _, payload := range unicodePayloads {
		// Add raw Unicode version
		finalPayloads = append(finalPayloads, payload)

		// Add fully URL-encoded version (encodes all UTF-8 bytes)
		encodedPayload := URLEncodeAll(payload)
		if encodedPayload != payload {
			finalPayloads = append(finalPayloads, encodedPayload)
		}
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf(
		"Total variants (with URL-encoded): %d payloads",
		len(finalPayloads),
	)

	// 6. Use the existing mid_paths generation logic with both raw and encoded variants
	return pg.generateMidPathsWithCustomPayloads(targetURL, bypassModule, finalPayloads)
}

// countSubstitutablePositions counts how many character positions can be substituted
// (excludes percent-encoded sequences)
func countSubstitutablePositions(payload string, charMap map[rune][]string) int {
	input := []byte(payload)
	count := 0

	for i := 0; i < len(input); {
		// Skip percent-encoded sequences
		if input[i] == '%' && i+2 < len(input) &&
			isHexDigitASCII(input[i+1]) && isHexDigitASCII(input[i+2]) {
			i += 3
			continue
		}

		// Decode rune and check if it's substitutable
		r, size := utf8.DecodeRune(input[i:])
		if _, ok := charMap[r]; ok {
			count++
		}

		i += size
	}

	return count
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
