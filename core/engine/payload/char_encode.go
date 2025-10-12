package payload

import (
	"fmt"
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

/*
GenerateCharEncodePayloads generates payloads by encoding characters in the URL path
using single, double, and triple URL encoding techniques.

The function implements five core encoding techniques:

 1. **Last Character Encoding:** Encodes the last character of the entire path.
    Example: `/admin/test` → `/admin/tes%74`

 2. **First Character Encoding:** Encodes the first character of the path (after any leading '/').
    Example: `/admin/test` → `/%61dmin/test`

 3. **Last Segment Character Encoding:** Encodes each character in the last path segment individually.
    Example: `/admin/test` → `/admin/%74est`, `/admin/t%65st`, etc.

 4. **Full Path Character Encoding:** Encodes each character in the entire path individually.
    Example: `/admin/test` → `/%61dmin/test`, `/a%64min/test`, etc.

 5. **Full Segment Encoding Variations:** Encodes all characters within complete path segments.
    Creates fully URL-encoded versions of each segment and generates payloads by:
    - Replacing individual segments: `/%61%64%6d%69%6e/test`, `/admin/%74%65%73%74`
    - Replacing all segments at once: `/%61%64%6d%69%6e/%74%65%73%74`

Each technique generates three encoding variants:
- Single encoding: `%61` (standard percent encoding)
- Double encoding: `%2561` (encoding the percent sign itself)
- Triple encoding: `%25%3561` (encoding the percent sign twice)

If the original path contains literal '?' or '#' characters, which are preserved
during the encoding process, the function also generates additional payloads where
these specific characters are percent-encoded (%3F and %23 respectively). This
ensures that the original query string can always be appended correctly.

All variations preserve the original query string if present.
*/
func (pg *PayloadGenerator) GenerateCharEncodePayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL: %s", targetURL)
		return allJobs
	}

	basePath := parsedURL.Path // Path might contain raw '?' or '#'
	query := ""
	// Preserve the original query string including the leading '?' using RawQuery
	if parsedURL.Query != "" {
		query = "?" + parsedURL.Query
	}

	// Using maps to automatically handle deduplication of final RawURIs
	singlePaths := make(map[string]struct{})
	doublePaths := make(map[string]struct{})
	triplePaths := make(map[string]struct{})

	// Base job template
	baseJob := BypassPayload{
		OriginalURL: targetURL,
		Method:      "GET", // Consider making method configurable or based on input
		Scheme:      parsedURL.Scheme,
		Host:        parsedURL.Host,
		// BypassModule field will be set specifically when creating jobs later
	}

	// 1. Process the last character of the path
	if len(basePath) > 0 {
		lastCharIndex := len(basePath) - 1
		lastChar := basePath[lastCharIndex]

		if isLetterASCII(lastChar) {
			encodedHex := fmt.Sprintf("%%%02x", lastChar)
			pathPrefix := basePath[:lastCharIndex]

			// --- Single Encoding ---
			singleEncodedPath := pathPrefix + encodedHex
			singlePaths[singleEncodedPath+query] = struct{}{} // Add base variant
			if strings.ContainsAny(singleEncodedPath, "?#") {
				encodedSpecialPath := encodeQueryAndFragmentChars(singleEncodedPath)
				singlePaths[encodedSpecialPath+query] = struct{}{} // Add special char encoded variant
			}

			// --- Double Encoding ---
			doubleEncodedPath := pathPrefix + "%25" + encodedHex[1:]
			doublePaths[doubleEncodedPath+query] = struct{}{}
			if strings.ContainsAny(doubleEncodedPath, "?#") {
				encodedSpecialPath := encodeQueryAndFragmentChars(doubleEncodedPath)
				doublePaths[encodedSpecialPath+query] = struct{}{}
			}

			// --- Triple Encoding ---
			tripleEncodedPath := pathPrefix + "%2525" + encodedHex[1:]
			triplePaths[tripleEncodedPath+query] = struct{}{}
			if strings.ContainsAny(tripleEncodedPath, "?#") {
				encodedSpecialPath := encodeQueryAndFragmentChars(tripleEncodedPath)
				triplePaths[encodedSpecialPath+query] = struct{}{}
			}
		}
	}

	// 2. Process the first character of the path
	if len(basePath) > 0 && basePath != "/" {
		firstCharIndex := 0
		if basePath[0] == '/' && len(basePath) > 1 {
			firstCharIndex = 1
		}

		// Ensure firstCharIndex is within bounds
		if firstCharIndex < len(basePath) {
			firstChar := basePath[firstCharIndex]

			if isLetterASCII(firstChar) {
				encodedHex := fmt.Sprintf("%%%02x", firstChar)
				pathPrefix := basePath[:firstCharIndex]
				pathSuffix := basePath[firstCharIndex+1:]

				// --- Single Encoding ---
				singleEncodedPath := pathPrefix + encodedHex + pathSuffix
				singlePaths[singleEncodedPath+query] = struct{}{}
				if strings.ContainsAny(singleEncodedPath, "?#") {
					encodedSpecialPath := encodeQueryAndFragmentChars(singleEncodedPath)
					singlePaths[encodedSpecialPath+query] = struct{}{}
				}

				// --- Double Encoding ---
				doubleEncodedPath := pathPrefix + "%25" + encodedHex[1:] + pathSuffix
				doublePaths[doubleEncodedPath+query] = struct{}{}
				if strings.ContainsAny(doubleEncodedPath, "?#") {
					encodedSpecialPath := encodeQueryAndFragmentChars(doubleEncodedPath)
					doublePaths[encodedSpecialPath+query] = struct{}{}
				}

				// --- Triple Encoding ---
				tripleEncodedPath := pathPrefix + "%2525" + encodedHex[1:] + pathSuffix
				triplePaths[tripleEncodedPath+query] = struct{}{}
				if strings.ContainsAny(tripleEncodedPath, "?#") {
					encodedSpecialPath := encodeQueryAndFragmentChars(tripleEncodedPath)
					triplePaths[encodedSpecialPath+query] = struct{}{}
				}
			}
		}
	}

	// 3. Process the last path segment
	if strings.Contains(basePath, "/") {
		segments := strings.Split(basePath, "/")
		lastSegmentIndex := -1
		for i := len(segments) - 1; i >= 0; i-- {
			if segments[i] != "" || i == 0 { // Consider root '/' case where segment[0] might be ""
				lastSegmentIndex = i
				break
			}
		}

		// Ensure a valid last segment was found
		if lastSegmentIndex != -1 && lastSegmentIndex < len(segments) {
			lastSegment := segments[lastSegmentIndex]

			// Reconstruct prefix carefully
			prefixSegments := segments[:lastSegmentIndex]
			prefix := strings.Join(prefixSegments, "/")
			// Adjust prefix based on original path structure
			if strings.HasPrefix(basePath, "/") && !strings.HasPrefix(prefix, "/") && len(prefixSegments) > 0 && prefix != "" {
				prefix = "/" + prefix // Add leading slash if original had one and prefix lost it (and prefix isn't already just "")
			} else if basePath == "/" || (strings.HasPrefix(basePath, "/") && len(prefixSegments) == 1 && prefixSegments[0] == "") {
				prefix = "/" // Handle cases like "/" or "/segment" correctly
			}
			// Add separator if needed (i.e. not encoding within the root segment itself if path is like "/a")
			if lastSegmentIndex > 0 || (len(segments) > 1 && segments[0] == "") { // Add separator if there are preceding segments or if it started with "/"
				if !strings.HasSuffix(prefix, "/") && lastSegment != "" { // Avoid double slash if prefix already ends with / or segment is empty
					prefix += "/"
				} else if prefix == "/" && lastSegment == "" && strings.HasSuffix(basePath, "//") {
					// Handle edge case like /a// -> prefix="/a/", lastSegment="" -> need prefix="/a/"
					prefix += "/"
				} else if prefix == "" && strings.HasPrefix(basePath, "/") && lastSegmentIndex == 1 {
					// Handle "/a" -> prefix="/", lastSegment="a"
					prefix = "/"
				}
			}

			// Iterate through the bytes of the identified last segment
			for i := 0; i < len(lastSegment); i++ {
				b := lastSegment[i]
				if isLetterASCII(b) {
					encodedHex := fmt.Sprintf("%%%02x", b)
					segmentPrefix := lastSegment[:i]
					segmentSuffix := lastSegment[i+1:]

					// --- Single Encoding ---
					singleEncodedPath := prefix + segmentPrefix + encodedHex + segmentSuffix
					singlePaths[singleEncodedPath+query] = struct{}{}
					if strings.ContainsAny(singleEncodedPath, "?#") {
						encodedSpecialPath := encodeQueryAndFragmentChars(singleEncodedPath)
						singlePaths[encodedSpecialPath+query] = struct{}{}
					}

					// --- Double Encoding ---
					doubleEncodedPath := prefix + segmentPrefix + "%25" + encodedHex[1:] + segmentSuffix
					doublePaths[doubleEncodedPath+query] = struct{}{}
					if strings.ContainsAny(doubleEncodedPath, "?#") {
						encodedSpecialPath := encodeQueryAndFragmentChars(doubleEncodedPath)
						doublePaths[encodedSpecialPath+query] = struct{}{}
					}

					// --- Triple Encoding ---
					tripleEncodedPath := prefix + segmentPrefix + "%2525" + encodedHex[1:] + segmentSuffix
					triplePaths[tripleEncodedPath+query] = struct{}{}
					if strings.ContainsAny(tripleEncodedPath, "?#") {
						encodedSpecialPath := encodeQueryAndFragmentChars(tripleEncodedPath)
						triplePaths[encodedSpecialPath+query] = struct{}{}
					}
				}
			}
		}
	} else if basePath != "" && basePath != "/" {
		// Handle case where basePath has no '/' (e.g., "admin") separately if needed,
		// though case 4 should cover it. If basePath has no '/' and is not empty,
		// it acts as the "last segment".
		lastSegment := basePath
		prefix := "" // No prefix
		for i := 0; i < len(lastSegment); i++ {
			b := lastSegment[i]
			if isLetterASCII(b) {
				encodedHex := fmt.Sprintf("%%%02x", b)
				segmentPrefix := lastSegment[:i]
				segmentSuffix := lastSegment[i+1:]

				// --- Single Encoding ---
				singleEncodedPath := prefix + segmentPrefix + encodedHex + segmentSuffix
				singlePaths[singleEncodedPath+query] = struct{}{}
				if strings.ContainsAny(singleEncodedPath, "?#") {
					encodedSpecialPath := encodeQueryAndFragmentChars(singleEncodedPath)
					singlePaths[encodedSpecialPath+query] = struct{}{}
				}

				// --- Double Encoding ---
				doubleEncodedPath := prefix + segmentPrefix + "%25" + encodedHex[1:] + segmentSuffix
				doublePaths[doubleEncodedPath+query] = struct{}{}
				if strings.ContainsAny(doubleEncodedPath, "?#") {
					encodedSpecialPath := encodeQueryAndFragmentChars(doubleEncodedPath)
					doublePaths[encodedSpecialPath+query] = struct{}{}
				}

				// --- Triple Encoding ---
				tripleEncodedPath := prefix + segmentPrefix + "%2525" + encodedHex[1:] + segmentSuffix
				triplePaths[tripleEncodedPath+query] = struct{}{}
				if strings.ContainsAny(tripleEncodedPath, "?#") {
					encodedSpecialPath := encodeQueryAndFragmentChars(tripleEncodedPath)
					triplePaths[encodedSpecialPath+query] = struct{}{}
				}
			}
		}
	}

	// 4. Process all letters in the entire path
	// This might overlap with cases 1, 2, 3 but maps handle deduplication.
	for i := 0; i < len(basePath); i++ {
		b := basePath[i]
		if isLetterASCII(b) {
			encodedHex := fmt.Sprintf("%%%02x", b)
			pathPrefix := basePath[:i]
			pathSuffix := basePath[i+1:]

			// --- Single Encoding ---
			singleEncodedPath := pathPrefix + encodedHex + pathSuffix
			singlePaths[singleEncodedPath+query] = struct{}{}
			if strings.ContainsAny(singleEncodedPath, "?#") {
				encodedSpecialPath := encodeQueryAndFragmentChars(singleEncodedPath)
				singlePaths[encodedSpecialPath+query] = struct{}{}
			}

			// --- Double Encoding ---
			doubleEncodedPath := pathPrefix + "%25" + encodedHex[1:] + pathSuffix
			doublePaths[doubleEncodedPath+query] = struct{}{}
			if strings.ContainsAny(doubleEncodedPath, "?#") {
				encodedSpecialPath := encodeQueryAndFragmentChars(doubleEncodedPath)
				doublePaths[encodedSpecialPath+query] = struct{}{}
			}

			// --- Triple Encoding ---
			tripleEncodedPath := pathPrefix + "%2525" + encodedHex[1:] + pathSuffix
			triplePaths[tripleEncodedPath+query] = struct{}{}
			if strings.ContainsAny(tripleEncodedPath, "?#") {
				encodedSpecialPath := encodeQueryAndFragmentChars(tripleEncodedPath)
				triplePaths[encodedSpecialPath+query] = struct{}{}
			}
		}
	}

	// 5. Full segment URL encoding variations
	if strings.Contains(basePath, "/") {
		segments := strings.Split(basePath, "/")
		if len(segments) > 1 {
			singleEncodedSegments := make([]string, len(segments))
			doubleEncodedSegments := make([]string, len(segments))
			tripleEncodedSegments := make([]string, len(segments))
			canBeEncoded := make([]bool, len(segments))
			anyCanBeEncoded := false

			// Generate encoded versions of each segment
			for i, segment := range segments {
				if segment == "" {
					continue
				}
				single, double, triple := urlEncodeSegment(segment)
				if single != segment {
					singleEncodedSegments[i] = single
					doubleEncodedSegments[i] = double
					tripleEncodedSegments[i] = triple
					canBeEncoded[i] = true
					anyCanBeEncoded = true
				}
			}

			if anyCanBeEncoded {
				// 5.1 Replace one segment at a time
				for i := 1; i < len(segments); i++ {
					if canBeEncoded[i] {
						singlePath := createPathWithReplacedSegment(segments, i, singleEncodedSegments[i])
						singlePaths[singlePath+query] = struct{}{}
						if strings.ContainsAny(singlePath, "?#") {
							encodedSpecialPath := encodeQueryAndFragmentChars(singlePath)
							singlePaths[encodedSpecialPath+query] = struct{}{}
						}

						doublePath := createPathWithReplacedSegment(segments, i, doubleEncodedSegments[i])
						doublePaths[doublePath+query] = struct{}{}
						if strings.ContainsAny(doublePath, "?#") {
							encodedSpecialPath := encodeQueryAndFragmentChars(doublePath)
							doublePaths[encodedSpecialPath+query] = struct{}{}
						}

						triplePath := createPathWithReplacedSegment(segments, i, tripleEncodedSegments[i])
						triplePaths[triplePath+query] = struct{}{}
						if strings.ContainsAny(triplePath, "?#") {
							encodedSpecialPath := encodeQueryAndFragmentChars(triplePath)
							triplePaths[encodedSpecialPath+query] = struct{}{}
						}
					}
				}

				// 5.2 Replace all possible segments at once
				numReplacable := 0
				for _, can := range canBeEncoded {
					if can {
						numReplacable++
					}
				}

				if numReplacable > 1 {
					tempSegmentsSingle := make([]string, len(segments))
					copy(tempSegmentsSingle, segments)
					tempSegmentsDouble := make([]string, len(segments))
					copy(tempSegmentsDouble, segments)
					tempSegmentsTriple := make([]string, len(segments))
					copy(tempSegmentsTriple, segments)

					for i := 1; i < len(segments); i++ {
						if canBeEncoded[i] {
							tempSegmentsSingle[i] = singleEncodedSegments[i]
							tempSegmentsDouble[i] = doubleEncodedSegments[i]
							tempSegmentsTriple[i] = tripleEncodedSegments[i]
						}
					}

					allSinglePath := "/" + strings.Join(tempSegmentsSingle[1:], "/")
					singlePaths[allSinglePath+query] = struct{}{}
					if strings.ContainsAny(allSinglePath, "?#") {
						encodedSpecialPath := encodeQueryAndFragmentChars(allSinglePath)
						singlePaths[encodedSpecialPath+query] = struct{}{}
					}

					allDoublePath := "/" + strings.Join(tempSegmentsDouble[1:], "/")
					doublePaths[allDoublePath+query] = struct{}{}
					if strings.ContainsAny(allDoublePath, "?#") {
						encodedSpecialPath := encodeQueryAndFragmentChars(allDoublePath)
						doublePaths[encodedSpecialPath+query] = struct{}{}
					}

					allTriplePath := "/" + strings.Join(tempSegmentsTriple[1:], "/")
					triplePaths[allTriplePath+query] = struct{}{}
					if strings.ContainsAny(allTriplePath, "?#") {
						encodedSpecialPath := encodeQueryAndFragmentChars(allTriplePath)
						triplePaths[encodedSpecialPath+query] = struct{}{}
					}
				}
			}
		}
	}

	// Create final jobs from the deduplicated maps
	createJobs := func(paths map[string]struct{}, moduleType string) {
		for rawURI := range paths {
			job := baseJob                               // Create a copy
			job.RawURI = rawURI                          // rawURI already includes the query string correctly
			job.BypassModule = moduleType                // Set specific module type
			job.PayloadToken = GeneratePayloadToken(job) // Generate token based on final job details
			allJobs = append(allJobs, job)
		}
	}

	createJobs(singlePaths, "char_encode")
	createJobs(doublePaths, "char_encode_double")
	createJobs(triplePaths, "char_encode_triple")

	// Log the total number of unique jobs created for this module group
	GB403Logger.Debug().BypassModule("char_encode").Msgf("Generated %d payloads for %s", len(allJobs), targetURL)
	return allJobs
}

// urlEncodeSegment converts a string segment into its single, double, and triple URL-encoded equivalents.
// Only encodes if the segment contains ASCII letters.
func urlEncodeSegment(segment string) (string, string, string) {
	var singleBuilder strings.Builder
	var doubleBuilder strings.Builder
	var tripleBuilder strings.Builder
	hasLetters := false

	// Iterate by bytes for ASCII letter encoding
	for i := 0; i < len(segment); i++ {
		b := segment[i]
		if isLetterASCII(b) {
			hasLetters = true
			// Single encoding
			singleBuilder.WriteString(fmt.Sprintf("%%%02x", b))
			// Double encoding
			doubleBuilder.WriteString(fmt.Sprintf("%%25%02x", b))
			// Triple encoding
			tripleBuilder.WriteString(fmt.Sprintf("%%2525%02x", b))
		} else {
			// Not a letter, keep as-is
			singleBuilder.WriteByte(b)
			doubleBuilder.WriteByte(b)
			tripleBuilder.WriteByte(b)
		}
	}

	if !hasLetters {
		// If no letters to encode, return original segment
		return segment, segment, segment
	}

	return singleBuilder.String(), doubleBuilder.String(), tripleBuilder.String()
}
