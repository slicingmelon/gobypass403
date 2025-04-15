package payload

import (
	"fmt"
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

/*
GenerateCharEncodePayloads generates payloads by encoding single characters
in the URL path using single, double, and triple URL encoding.

It handles four cases for character encoding:
1. The last character of the path.
2. The first character of the path (after any leading '/').
3. Each character in the last path segment.
4. Each character in the entire path.

If the original path contains literal '?' or '#' characters, which are
preserved during the letter-encoding process, this function also generates
additional payloads where these specific '?' and '#' characters are
percent-encoded (%3F and %23 respectively). This ensures that the original
query string can always be appended correctly.
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

		if isLetter(lastChar) {
			encodedHex := fmt.Sprintf("%%%02x", lastChar)
			pathPrefix := basePath[:lastCharIndex]

			// --- Single Encoding ---
			singleEncodedPath := pathPrefix + encodedHex
			singlePaths[singleEncodedPath+query] = struct{}{} // Add base variant
			if strings.ContainsAny(singleEncodedPath, "?#") {
				encodedSpecialPath := encodePathSpecialChars(singleEncodedPath)
				singlePaths[encodedSpecialPath+query] = struct{}{} // Add special char encoded variant
			}

			// --- Double Encoding ---
			doubleEncodedPath := pathPrefix + "%25" + encodedHex[1:]
			doublePaths[doubleEncodedPath+query] = struct{}{}
			if strings.ContainsAny(doubleEncodedPath, "?#") {
				encodedSpecialPath := encodePathSpecialChars(doubleEncodedPath)
				doublePaths[encodedSpecialPath+query] = struct{}{}
			}

			// --- Triple Encoding ---
			tripleEncodedPath := pathPrefix + "%2525" + encodedHex[1:]
			triplePaths[tripleEncodedPath+query] = struct{}{}
			if strings.ContainsAny(tripleEncodedPath, "?#") {
				encodedSpecialPath := encodePathSpecialChars(tripleEncodedPath)
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

			if isLetter(firstChar) {
				encodedHex := fmt.Sprintf("%%%02x", firstChar)
				pathPrefix := basePath[:firstCharIndex]
				pathSuffix := basePath[firstCharIndex+1:]

				// --- Single Encoding ---
				singleEncodedPath := pathPrefix + encodedHex + pathSuffix
				singlePaths[singleEncodedPath+query] = struct{}{}
				if strings.ContainsAny(singleEncodedPath, "?#") {
					encodedSpecialPath := encodePathSpecialChars(singleEncodedPath)
					singlePaths[encodedSpecialPath+query] = struct{}{}
				}

				// --- Double Encoding ---
				doubleEncodedPath := pathPrefix + "%25" + encodedHex[1:] + pathSuffix
				doublePaths[doubleEncodedPath+query] = struct{}{}
				if strings.ContainsAny(doubleEncodedPath, "?#") {
					encodedSpecialPath := encodePathSpecialChars(doubleEncodedPath)
					doublePaths[encodedSpecialPath+query] = struct{}{}
				}

				// --- Triple Encoding ---
				tripleEncodedPath := pathPrefix + "%2525" + encodedHex[1:] + pathSuffix
				triplePaths[tripleEncodedPath+query] = struct{}{}
				if strings.ContainsAny(tripleEncodedPath, "?#") {
					encodedSpecialPath := encodePathSpecialChars(tripleEncodedPath)
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

			// Iterate through the characters of the identified last segment
			for i, char := range lastSegment {
				if isLetter(byte(char)) {
					encodedHex := fmt.Sprintf("%%%02x", char)
					segmentPrefix := lastSegment[:i]
					segmentSuffix := lastSegment[i+1:]

					// --- Single Encoding ---
					singleEncodedPath := prefix + segmentPrefix + encodedHex + segmentSuffix
					singlePaths[singleEncodedPath+query] = struct{}{}
					if strings.ContainsAny(singleEncodedPath, "?#") {
						encodedSpecialPath := encodePathSpecialChars(singleEncodedPath)
						singlePaths[encodedSpecialPath+query] = struct{}{}
					}

					// --- Double Encoding ---
					doubleEncodedPath := prefix + segmentPrefix + "%25" + encodedHex[1:] + segmentSuffix
					doublePaths[doubleEncodedPath+query] = struct{}{}
					if strings.ContainsAny(doubleEncodedPath, "?#") {
						encodedSpecialPath := encodePathSpecialChars(doubleEncodedPath)
						doublePaths[encodedSpecialPath+query] = struct{}{}
					}

					// --- Triple Encoding ---
					tripleEncodedPath := prefix + segmentPrefix + "%2525" + encodedHex[1:] + segmentSuffix
					triplePaths[tripleEncodedPath+query] = struct{}{}
					if strings.ContainsAny(tripleEncodedPath, "?#") {
						encodedSpecialPath := encodePathSpecialChars(tripleEncodedPath)
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
		for i, char := range lastSegment {
			if isLetter(byte(char)) {
				encodedHex := fmt.Sprintf("%%%02x", char)
				segmentPrefix := lastSegment[:i]
				segmentSuffix := lastSegment[i+1:]

				// --- Single Encoding ---
				singleEncodedPath := prefix + segmentPrefix + encodedHex + segmentSuffix
				singlePaths[singleEncodedPath+query] = struct{}{}
				if strings.ContainsAny(singleEncodedPath, "?#") {
					encodedSpecialPath := encodePathSpecialChars(singleEncodedPath)
					singlePaths[encodedSpecialPath+query] = struct{}{}
				}

				// --- Double Encoding ---
				doubleEncodedPath := prefix + segmentPrefix + "%25" + encodedHex[1:] + segmentSuffix
				doublePaths[doubleEncodedPath+query] = struct{}{}
				if strings.ContainsAny(doubleEncodedPath, "?#") {
					encodedSpecialPath := encodePathSpecialChars(doubleEncodedPath)
					doublePaths[encodedSpecialPath+query] = struct{}{}
				}

				// --- Triple Encoding ---
				tripleEncodedPath := prefix + segmentPrefix + "%2525" + encodedHex[1:] + segmentSuffix
				triplePaths[tripleEncodedPath+query] = struct{}{}
				if strings.ContainsAny(tripleEncodedPath, "?#") {
					encodedSpecialPath := encodePathSpecialChars(tripleEncodedPath)
					triplePaths[encodedSpecialPath+query] = struct{}{}
				}
			}
		}
	}

	// 4. Process all letters in the entire path
	// This might overlap with cases 1, 2, 3 but maps handle deduplication.
	for i := 0; i < len(basePath); i++ {
		char := basePath[i]
		if isLetter(byte(char)) {
			encodedHex := fmt.Sprintf("%%%02x", char)
			pathPrefix := basePath[:i]
			pathSuffix := basePath[i+1:]

			// --- Single Encoding ---
			singleEncodedPath := pathPrefix + encodedHex + pathSuffix
			singlePaths[singleEncodedPath+query] = struct{}{}
			if strings.ContainsAny(singleEncodedPath, "?#") {
				encodedSpecialPath := encodePathSpecialChars(singleEncodedPath)
				singlePaths[encodedSpecialPath+query] = struct{}{}
			}

			// --- Double Encoding ---
			doubleEncodedPath := pathPrefix + "%25" + encodedHex[1:] + pathSuffix
			doublePaths[doubleEncodedPath+query] = struct{}{}
			if strings.ContainsAny(doubleEncodedPath, "?#") {
				encodedSpecialPath := encodePathSpecialChars(doubleEncodedPath)
				doublePaths[encodedSpecialPath+query] = struct{}{}
			}

			// --- Triple Encoding ---
			tripleEncodedPath := pathPrefix + "%2525" + encodedHex[1:] + pathSuffix
			triplePaths[tripleEncodedPath+query] = struct{}{}
			if strings.ContainsAny(tripleEncodedPath, "?#") {
				encodedSpecialPath := encodePathSpecialChars(tripleEncodedPath)
				triplePaths[encodedSpecialPath+query] = struct{}{}
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
