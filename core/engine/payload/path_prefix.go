package payload

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

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
	if leadingSlash && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if !leadingSlash && path == "" && len(segments) == 1 && segments[0] == "" {
		return "" // Original was ""
	}

	// Don't add trailing slash if it's just the root "/"
	// Preserve original trailing slash only if no segments were truly added/modified at the end
	if trailingSlash && path != "/" && !strings.HasSuffix(path, "/") {
		lastSegment := ""
		if len(segments) > 0 {
			lastSegment = segments[len(segments)-1]
		}
		// Simple check, might need expansion based on generated prefixes
		// If the last segment is short and non-alphanumeric, assume it was added, don't restore slash.
		if len(lastSegment) > 0 && len(lastSegment) < 4 && !isAlphanumeric(lastSegment[0]) {
			// Likely an added prefix, don't restore trailing slash
		} else {
			path = path + "/"
		}
	}
	return path
}

// isControlByte checks if a byte is an ASCII control character (0x00-0x1F, 0x7F)
func isControlByte(b byte) bool {
	return (b >= 0x00 && b <= 0x1F) || b == 0x7F
}

// isSpecialCharASCII checks if a byte is an ASCII special character (punctuation or symbol within 0-127)
// !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~
func isSpecialCharASCII(b byte) bool {
	// Ensure it's within ASCII range first
	if b > 127 {
		return false
	}
	// Use standard Go functions for ASCII range checks which are efficient
	// or check against a predefined string/map for ASCII punctuation/symbols if preferred.
	// Using unicode functions is fine as they handle ASCII correctly and efficiently.
	r := rune(b)
	return unicode.IsPunct(r) || unicode.IsSymbol(r)
}

// isAlphanumeric checks if a byte is a standard ASCII letter or digit.
func isAlphanumeric(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// GeneratePathPrefixPayloads generates payloads by prefixing segments/path
// with single bytes (ASCII ctrl, ASCII special, 'x') and two-byte combinations
// (raw+raw, enc+enc) using these categories.
// Dummy segment prefix uses single bytes (raw, encoded) only.
func (pg *PayloadGenerator) GeneratePathPrefixPayloads(targetURL string, bypassModule string) []BypassPayload {
	var jobs []BypassPayload
	uniquePaths := make(map[string]struct{}) // Use map to ensure unique RawURIs

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL '%s': %v", targetURL, err)
		return jobs
	}

	originalPath := parsedURL.Path
	if originalPath == "" {
		originalPath = "/" // Treat empty path as root
	}

	// Extract query string if it exists
	query := ""
	if parsedURL.Query != "" {
		query = "?" + parsedURL.Query
	}

	// Determine path structure
	hasLeadingSlash := strings.HasPrefix(originalPath, "/")
	hasTrailingSlash := strings.HasSuffix(originalPath, "/") && originalPath != "/"

	// Get segments
	trimmedPath := strings.Trim(originalPath, "/")
	var originalSegments []string
	if trimmedPath == "" && originalPath == "/" {
		originalSegments = []string{""} // Root path means one empty segment conceptually for prefixing/dummy
	} else if trimmedPath == "" {
		originalSegments = []string{} // Empty path
	} else {
		originalSegments = strings.Split(trimmedPath, "/")
	}

	canModifySegments := len(originalSegments) > 0 && !(len(originalSegments) == 1 && originalSegments[0] == "")

	// --- Byte Iteration Loop (Filtered: ASCII Control, ASCII Special, 'x') ---
	for i := 0; i < 256; i++ {
		b1 := byte(i)

		// Filter: Only include ASCII control chars, ASCII special chars, or 'x'
		isRelevantByte1 := isControlByte(b1) || isSpecialCharASCII(b1) || b1 == 'x'
		if !isRelevantByte1 {
			continue
		}

		rawB1Str := string([]byte{b1})
		encodedB1Str := fmt.Sprintf("%%%02X", b1)

		// == Variation: Dummy Segment Prefix (Single Byte Only - Raw/Encoded) ==
		// Using raw and single encoded bytes
		for _, prefix := range []string{rawB1Str, encodedB1Str} {
			dummySegments := make([]string, 0, len(originalSegments)+1)
			dummySegments = append(dummySegments, prefix)
			dummySegments = append(dummySegments, originalSegments...)
			uniquePaths[buildPath(dummySegments, hasLeadingSlash, hasTrailingSlash)+query] = struct{}{}
		}

		// == Segment-based Variations (Prefix Only - Single Byte - Raw/Encoded) ==
		if canModifySegments {
			for j := range originalSegments {
				// Only Prefix variations are kept
				variations := []struct {
					name   string
					prefix string
				}{
					{"SingleByteRawPfx", rawB1Str},
					{"SingleByteEncPfx", encodedB1Str},
				}

				for _, v := range variations {
					modSegs := make([]string, len(originalSegments))
					copy(modSegs, originalSegments)
					modSegs[j] = v.prefix + originalSegments[j] // Apply prefix
					uniquePaths[buildPath(modSegs, hasLeadingSlash, hasTrailingSlash)+query] = struct{}{}
				}
			}
		}

		// == Variation: Two-Byte Prefix for Existing Segments (ASCII Control/Special/'x') (Raw+Raw, Enc+Enc) ==
		if canModifySegments {
			for k := 0; k < 256; k++ {
				b2 := byte(k)
				// Filter: Only include combinations where b2 is also an ASCII control char, ASCII special char, or 'x'
				isRelevantByte2 := isControlByte(b2) || isSpecialCharASCII(b2) || b2 == 'x'
				if !isRelevantByte2 {
					continue // Second byte must also be relevant
				}

				// Generate 2 encoding variations for the two bytes (Raw+Raw, Enc+Enc)
				encodings := []string{
					string([]byte{b1, b2}),              // Raw+Raw
					fmt.Sprintf("%%%02X%%%02X", b1, b2), // Enc+Enc
				}

				// Apply variations ONLY to existing segments
				for _, combo := range encodings {
					// Existing Segment Prefix: /HEREHEREadmin/login, /admin/HEREHERElogin etc.
					for j := range originalSegments {
						modSegsPfx := make([]string, len(originalSegments))
						copy(modSegsPfx, originalSegments)
						modSegsPfx[j] = combo + originalSegments[j]
						uniquePaths[buildPath(modSegsPfx, hasLeadingSlash, hasTrailingSlash)+query] = struct{}{}
					}
				}
			}
		}
	} // End main loop (i=0 to 255)

	// Convert unique paths map to BypassPayload slice
	for rawURI := range uniquePaths {
		job := BypassPayload{
			OriginalURL:  targetURL,
			Method:       "GET", // Defaulting to GET
			Scheme:       parsedURL.Scheme,
			Host:         parsedURL.Host,
			RawURI:       rawURI,
			BypassModule: bypassModule,
		}
		job.PayloadToken = GeneratePayloadToken(job)
		jobs = append(jobs, job)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d ASCII-focused byte prefix payloads (raw/enc, ctrl/spec/'x', single-byte dummy) for %s\n", len(jobs), targetURL)
	return jobs
}
