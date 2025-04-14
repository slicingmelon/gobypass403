package payload

import (
	"fmt"
	"strings"

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
	// This check might need refinement depending on exact desired behavior for dummy segments vs modifications
	if trailingSlash && path != "/" && !strings.HasSuffix(path, "/") {
		// Heuristic: if the last segment looks like one of our added prefixes, don't add trailing slash back
		// This is imperfect. A better way might be needed if strict trailing slash preservation is critical.
		lastSegment := ""
		if len(segments) > 0 {
			lastSegment = segments[len(segments)-1]
		}
		// Simple check, might need expansion based on generated prefixes
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

// isAlphanumeric checks if a byte is a standard ASCII letter or digit.
func isAlphanumeric(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// GeneratePathPrefixPayloads generates payloads by prefixing segments/path
// with single bytes (excluding most alphanumerics), common bypass sequences,
// double encodings, and two control bytes. Focuses only on prefixing.
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
	// Trailing slash status is noted but buildPath will handle reconstruction based on modifications
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

	// --- Common Bypass Sequences ---
	commonBypassChars := []string{".", ";", "..", "%2e", "%2f", "//", "%09", "%00"}
	canModifySegments := len(originalSegments) > 0 && !(len(originalSegments) == 1 && originalSegments[0] == "")

	for _, bypassChar := range commonBypassChars {
		// Variation: Dummy Segment Prefix with common bypass chars
		dummySegs := make([]string, 0, len(originalSegments)+1)
		dummySegs = append(dummySegs, bypassChar)
		dummySegs = append(dummySegs, originalSegments...)
		// Pass original trailing slash status to buildPath
		uniquePaths[buildPath(dummySegs, hasLeadingSlash, hasTrailingSlash)+query] = struct{}{}

		// Variation: Prefix existing segments with common bypass chars
		if canModifySegments {
			for j := range originalSegments {
				// Prefix Only
				modSegsPfx := make([]string, len(originalSegments))
				copy(modSegsPfx, originalSegments)
				modSegsPfx[j] = bypassChar + originalSegments[j]
				// Pass original trailing slash status to buildPath
				uniquePaths[buildPath(modSegsPfx, hasLeadingSlash, hasTrailingSlash)+query] = struct{}{}

				// --- Suffix part removed ---
			}
		}
	}

	// --- Byte Iteration Loop (Filtered) ---
	for i := 0; i < 256; i++ {
		b1 := byte(i)

		// Skip most alphanumeric characters, keep 'x' as representative
		if isAlphanumeric(b1) && b1 != 'x' {
			continue
		}

		rawB1Str := string([]byte{b1})
		encodedB1Str := fmt.Sprintf("%%%02X", b1)
		doubleEncodedB1Str := "%25" + fmt.Sprintf("%02X", b1) // Double encoding % -> %25

		// == Variation: Dummy Segment Prefix (add new first segment) ==
		// Using raw, single encoded, and double encoded bytes
		for _, prefix := range []string{rawB1Str, encodedB1Str, doubleEncodedB1Str} {
			// Skip double encoding non-printable or already encoded-like common chars to avoid noise like %25%2F
			if prefix == doubleEncodedB1Str && (isControlByte(b1) || strings.HasPrefix(rawB1Str, "%") || strings.ContainsAny(rawB1Str, "./;")) {
				continue
			}
			dummySegments := make([]string, 0, len(originalSegments)+1)
			dummySegments = append(dummySegments, prefix)
			dummySegments = append(dummySegments, originalSegments...)
			// Pass original trailing slash status to buildPath
			uniquePaths[buildPath(dummySegments, hasLeadingSlash, hasTrailingSlash)+query] = struct{}{}
		}

		// == Segment-based Variations (Prefix Only) ==
		if canModifySegments {
			for j := range originalSegments {
				// Only Prefix variations are kept
				variations := []struct {
					name   string
					prefix string
				}{
					{"SingleByteRawPfx", rawB1Str},
					{"SingleByteEncPfx", encodedB1Str},
					{"DoubleByteEncPfx", doubleEncodedB1Str},
				}

				for _, v := range variations {
					// Skip double encoding non-printable or already encoded-like common chars here too
					if v.prefix == doubleEncodedB1Str && (isControlByte(b1) || strings.HasPrefix(rawB1Str, "%") || strings.ContainsAny(rawB1Str, "./;")) {
						continue
					}

					modSegs := make([]string, len(originalSegments))
					copy(modSegs, originalSegments)
					modSegs[j] = v.prefix + originalSegments[j] // Apply prefix
					// Pass original trailing slash status to buildPath
					uniquePaths[buildPath(modSegs, hasLeadingSlash, hasTrailingSlash)+query] = struct{}{}
				}
			}
		}

		// == Variation: Two-Byte Control Character Prefix (Multiple Encodings) ==
		// Keep this as is, but it now operates on b1 which is already filtered
		if canModifySegments && isControlByte(b1) {
			for k := 0; k < 256; k++ {
				b2 := byte(k)
				if !isControlByte(b2) {
					continue // Both must be control bytes
				}

				// Generate 4 encoding variations for the two bytes
				encodings := []string{
					string([]byte{b1, b2}),                         // Raw+Raw
					fmt.Sprintf("%%%02X%%%02X", b1, b2),            // Enc+Enc
					string([]byte{b1}) + fmt.Sprintf("%%%02X", b2), // Raw+Enc
					fmt.Sprintf("%%%02X", b1) + string([]byte{b2}), // Enc+Raw
				}

				for _, combo := range encodings {
					for j := range originalSegments {
						// Apply as Prefix Only
						modSegsPfx := make([]string, len(originalSegments))
						copy(modSegsPfx, originalSegments)
						modSegsPfx[j] = combo + originalSegments[j]
						// Pass original trailing slash status to buildPath
						uniquePaths[buildPath(modSegsPfx, hasLeadingSlash, hasTrailingSlash)+query] = struct{}{}

						// --- Suffix part removed ---
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

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d prefix-only payloads for %s\n", len(jobs), targetURL)
	return jobs
}
