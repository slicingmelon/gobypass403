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
	if trailingSlash && path != "/" && !strings.HasSuffix(path, "/") {
		path = path + "/"
	}
	return path
}

// isControlByte checks if a byte is an ASCII control character (0x00-0x1F, 0x7F)
func isControlByte(b byte) bool {
	return (b >= 0x00 && b <= 0x1F) || b == 0x7F
}

// GeneratePathPrefixPayloads generates payloads by prefixing/suffixing segments/path
// with single bytes, two control bytes (multiple encodings), or adding a dummy first segment.
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
		originalSegments = []string{""} // Root path
	} else if trimmedPath == "" {
		originalSegments = []string{} // Empty path
	} else {
		originalSegments = strings.Split(trimmedPath, "/")
	}

	if len(originalSegments) == 0 && originalPath != "/" {
		GB403Logger.Debug().BypassModule(bypassModule).Msgf("Skipping prefix generation for empty path '%s'\n", targetURL)
		return jobs
	}

	// --- Generation Loop ---
	for i := 0; i < 256; i++ {
		b1 := byte(i)
		rawB1Str := string([]byte{b1})
		encodedB1Str := fmt.Sprintf("%%%02X", b1)

		// == Variation: Dummy Segment Prefix (add new first segment) ==
		// /BYTE/admin/login or /%XX/admin/login ; /BYTE/ or /%XX/
		dummySegmentsRaw := make([]string, 0, len(originalSegments)+1)
		dummySegmentsRaw = append(dummySegmentsRaw, rawB1Str)
		dummySegmentsRaw = append(dummySegmentsRaw, originalSegments...)
		uniquePaths[buildPath(dummySegmentsRaw, hasLeadingSlash, hasTrailingSlash)+query] = struct{}{}

		dummySegmentsEnc := make([]string, 0, len(originalSegments)+1)
		dummySegmentsEnc = append(dummySegmentsEnc, encodedB1Str)
		dummySegmentsEnc = append(dummySegmentsEnc, originalSegments...)
		uniquePaths[buildPath(dummySegmentsEnc, hasLeadingSlash, hasTrailingSlash)+query] = struct{}{}

		// == Segment-based Variations (Prefix/Suffix) ==
		if len(originalSegments) > 0 && !(len(originalSegments) == 1 && originalSegments[0] == "") { // Skip segment mods if path was just "/"
			for j := range originalSegments {
				// == Variation: Single Byte Prefix ==
				modSegsPfxRaw := make([]string, len(originalSegments))
				copy(modSegsPfxRaw, originalSegments)
				modSegsPfxRaw[j] = rawB1Str + originalSegments[j]
				uniquePaths[buildPath(modSegsPfxRaw, hasLeadingSlash, hasTrailingSlash)+query] = struct{}{}

				modSegsPfxEnc := make([]string, len(originalSegments))
				copy(modSegsPfxEnc, originalSegments)
				modSegsPfxEnc[j] = encodedB1Str + originalSegments[j]
				uniquePaths[buildPath(modSegsPfxEnc, hasLeadingSlash, hasTrailingSlash)+query] = struct{}{}

				// == Variation: Single Byte Suffix ==
				modSegsSfxRaw := make([]string, len(originalSegments))
				copy(modSegsSfxRaw, originalSegments)
				modSegsSfxRaw[j] = originalSegments[j] + rawB1Str
				uniquePaths[buildPath(modSegsSfxRaw, hasLeadingSlash, hasTrailingSlash)+query] = struct{}{}

				modSegsSfxEnc := make([]string, len(originalSegments))
				copy(modSegsSfxEnc, originalSegments)
				modSegsSfxEnc[j] = originalSegments[j] + encodedB1Str
				uniquePaths[buildPath(modSegsSfxEnc, hasLeadingSlash, hasTrailingSlash)+query] = struct{}{}
			}
		}

		// == Variation: Two-Byte Control Character Prefix/Suffix (Multiple Encodings) ==
		if len(originalSegments) > 0 && !(len(originalSegments) == 1 && originalSegments[0] == "") && isControlByte(b1) {
			for k := 0; k < 256; k++ {
				b2 := byte(k)
				if !isControlByte(b2) {
					continue
				} // Both must be control bytes

				// Generate 4 encoding variations for the two bytes
				encodings := []string{
					string([]byte{b1, b2}),                         // Raw+Raw
					fmt.Sprintf("%%%02X%%%02X", b1, b2),            // Enc+Enc
					string([]byte{b1}) + fmt.Sprintf("%%%02X", b2), // Raw+Enc
					fmt.Sprintf("%%%02X", b1) + string([]byte{b2}), // Enc+Raw
				}

				for _, prefix := range encodings {
					for j := range originalSegments {
						// Apply as Prefix
						modSegsPfx := make([]string, len(originalSegments))
						copy(modSegsPfx, originalSegments)
						modSegsPfx[j] = prefix + originalSegments[j]
						uniquePaths[buildPath(modSegsPfx, hasLeadingSlash, hasTrailingSlash)+query] = struct{}{}

						// Apply as Suffix
						modSegsSfx := make([]string, len(originalSegments))
						copy(modSegsSfx, originalSegments)
						modSegsSfx[j] = originalSegments[j] + prefix
						uniquePaths[buildPath(modSegsSfx, hasLeadingSlash, hasTrailingSlash)+query] = struct{}{}
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

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(jobs), targetURL)
	return jobs
}
