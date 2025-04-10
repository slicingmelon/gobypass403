package payload

import (
	"fmt"
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

/*
GenerateCharEncodePayloads
*/
func (pg *PayloadGenerator) GenerateCharEncodePayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
		return allJobs
	}

	basePath := parsedURL.Path

	// Extract query string if it exists
	query := ""
	if parsedURL.Query != "" {
		query = "?" + parsedURL.Query
	}

	// Create separate maps for different encoding levels
	singlePaths := make(map[string]struct{})
	doublePaths := make(map[string]struct{})
	triplePaths := make(map[string]struct{})

	// Base job template
	baseJob := BypassPayload{
		OriginalURL:  targetURL,
		Method:       "GET",
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		BypassModule: bypassModule,
	}

	// 1. First process the last character of the path
	if len(basePath) > 0 {
		lastCharIndex := len(basePath) - 1
		lastChar := basePath[lastCharIndex]

		// Only encode if it's a letter
		if isLetter(lastChar) {
			// Single URL encoding for last character
			encoded := fmt.Sprintf("%%%02x", lastChar)
			singleEncoded := basePath[:lastCharIndex] + encoded
			singlePaths[singleEncoded+query] = struct{}{}

			// Double URL encoding for last character
			doubleEncoded := basePath[:lastCharIndex] + "%25" + encoded[1:]
			doublePaths[doubleEncoded+query] = struct{}{}

			// Triple URL encoding for last character
			tripleEncoded := basePath[:lastCharIndex] + "%2525" + encoded[1:]
			triplePaths[tripleEncoded+query] = struct{}{}
		}
	}

	// 2. Process the first character of the path
	if len(basePath) > 0 && basePath != "/" {
		firstCharIndex := 0
		// Skip leading slash if present
		if basePath[0] == '/' && len(basePath) > 1 {
			firstCharIndex = 1
		}

		firstChar := basePath[firstCharIndex]

		// Only encode if it's a letter
		if isLetter(firstChar) {
			// Single URL encoding for first character
			encoded := fmt.Sprintf("%%%02x", firstChar)
			singleEncoded := basePath[:firstCharIndex] + encoded + basePath[firstCharIndex+1:]
			singlePaths[singleEncoded+query] = struct{}{}

			// Double URL encoding for first character
			doubleEncoded := basePath[:firstCharIndex] + "%25" + encoded[1:] + basePath[firstCharIndex+1:]
			doublePaths[doubleEncoded+query] = struct{}{}

			// Triple URL encoding for first character
			tripleEncoded := basePath[:firstCharIndex] + "%2525" + encoded[1:] + basePath[firstCharIndex+1:]
			triplePaths[tripleEncoded+query] = struct{}{}
		}
	}

	// 3. Process the last path segment
	if len(basePath) > 0 {
		segments := strings.Split(basePath, "/")
		if len(segments) > 1 {
			lastSegment := segments[len(segments)-1]

			// Skip empty segments
			if lastSegment != "" {
				// Process last segment
				for i, char := range lastSegment {
					if isLetter(byte(char)) {
						// Build the path prefix (everything before the last segment)
						prefix := strings.Join(segments[:len(segments)-1], "/") + "/"

						// Single URL encoding
						encoded := fmt.Sprintf("%%%02x", char)
						singleEncoded := prefix + lastSegment[:i] + encoded + lastSegment[i+1:]
						singlePaths[singleEncoded+query] = struct{}{}

						// Double URL encoding
						doubleEncoded := prefix + lastSegment[:i] + "%25" + encoded[1:] + lastSegment[i+1:]
						doublePaths[doubleEncoded+query] = struct{}{}

						// Triple URL encoding
						tripleEncoded := prefix + lastSegment[:i] + "%2525" + encoded[1:] + lastSegment[i+1:]
						triplePaths[tripleEncoded+query] = struct{}{}
					}
				}
			}
		}
	}

	// 4. Find all letter positions in the entire path
	for i, char := range basePath {
		if isLetter(byte(char)) {
			// Single URL encoding
			encoded := fmt.Sprintf("%%%02x", char)
			singleEncoded := basePath[:i] + encoded + basePath[i+1:]
			singlePaths[singleEncoded+query] = struct{}{}

			// Double URL encoding
			doubleEncoded := basePath[:i] + "%25" + encoded[1:] + basePath[i+1:]
			doublePaths[doubleEncoded+query] = struct{}{}

			// Triple URL encoding
			tripleEncoded := basePath[:i] + "%2525" + encoded[1:] + basePath[i+1:]
			triplePaths[tripleEncoded+query] = struct{}{}
		}
	}

	// Helper function to create jobs
	createJobs := func(paths map[string]struct{}, moduleType string) {
		for rawURI := range paths {
			job := baseJob
			job.RawURI = rawURI
			job.BypassModule = moduleType
			job.PayloadToken = GeneratePayloadToken(job)
			allJobs = append(allJobs, job)
		}
	}

	// Create jobs for each encoding level
	createJobs(singlePaths, "char_encode")
	createJobs(doublePaths, "char_encode_double")
	createJobs(triplePaths, "char_encode_triple")

	totalJobs := len(singlePaths) + len(doublePaths) + len(triplePaths)
	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", totalJobs, targetURL)
	return allJobs
}
