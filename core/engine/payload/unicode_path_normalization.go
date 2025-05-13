package payload

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

// UnicodeMapping represents a single Unicode character that normalizes to an ASCII character
type UnicodeMapping struct {
	Unicode         string `json:"unicode"`
	UTF8Bytes       string `json:"utf8_bytes"`
	URLEncoded      string `json:"url_encoded"`
	NormalizeAs     string `json:"normalizes_as"`
	NormalizesAsHex string `json:"normalizes_as_hex"`
	Form            string `json:"form"`
}

// OrderedCharMap represents an ASCII character and its Unicode mappings
type OrderedCharMap struct {
	ASCII    int              `json:"ascii"`
	Char     string           `json:"char"`
	Mappings []UnicodeMapping `json:"mappings"`
}

// ReadUnicodeCharMap reads the unicode_char_map.json file
func ReadUnicodeCharMap() ([]OrderedCharMap, error) {
	// Try reading from local directory first
	content, err := ReadPayloadsFromJSONFile("unicode_char_map.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read unicode_char_map.json: %w", err)
	}

	var charMap []OrderedCharMap
	if err := json.Unmarshal(content, &charMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal unicode_char_map.json: %w", err)
	}

	return charMap, nil
}

/*
GenerateUnicodePathNormalizationsPayloads generates payloads based on Unicode
normalization bypass techniques, targeting path characters with unicode variants.

The function uses unicode_char_map.json which contains mappings from ASCII to
Unicode characters that normalize to the ASCII character.

Payload generation techniques include:
 1. **Path Separator Variations:** Generates variations with double slashes (e.g., "//admin/login").
 2. **Unicode Path Character Variations:** Replaces path characters with their Unicode equivalents.
    This includes raw Unicode, URL-encoded, and UTF-8 byte representations.
 3. **Path Segment Character Variations:** Replaces characters within path segments.
    Focuses especially on first and last characters of each segment.
 4. **Mixed Character Variations:** Creates combinations of different Unicode representations.

All variations preserve the original query string if present.
*/
func (pg *PayloadGenerator) GenerateUnicodePathNormalizationsPayloads(targetURL string, bypassModule string) []BypassPayload {
	var jobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().BypassModule(bypassModule).Msgf("Failed to parse URL: %v", err)
		return jobs
	}

	path := parsedURL.Path
	if path == "" {
		path = "/"
	}

	// Extract query string if it exists
	query := ""
	if parsedURL.Query != "" {
		query = "?" + parsedURL.Query
	}

	// Read the unicode character map
	charMap, err := ReadUnicodeCharMap()
	if err != nil {
		GB403Logger.Error().BypassModule(bypassModule).Msgf("Failed to read unicode_char_map.json: %v", err)
		return jobs
	}

	// Build a more efficient lookup map: ASCII int -> []UnicodeMapping
	asciiToMappings := make(map[int][]UnicodeMapping)
	for _, entry := range charMap {
		asciiToMappings[entry.ASCII] = entry.Mappings
	}

	baseJob := BypassPayload{
		OriginalURL:  targetURL,
		Method:       "GET",
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		BypassModule: bypassModule,
	}

	uniquePaths := make(map[string]struct{}) // Track generated URIs to avoid duplicates

	// Helper to add a job if the URI is unique
	addJob := func(uri string) {
		if _, exists := uniquePaths[uri]; !exists {
			uniquePaths[uri] = struct{}{}
			job := baseJob
			job.RawURI = uri
			job.PayloadToken = GeneratePayloadToken(job)
			jobs = append(jobs, job)
		}
	}

	// --- 1. Double-slash variations ---
	segments := strings.Split(path, "/")
	if len(segments) > 1 {
		// Insert double slashes at each path separator
		for i := 1; i < len(segments); i++ {
			if segments[i] == "" {
				continue // Skip empty segments
			}

			// Create path with double slash
			var doubleSlashPath strings.Builder
			doubleSlashPath.WriteString("/")
			for j := 1; j < len(segments); j++ {
				if j == i {
					doubleSlashPath.WriteString("/") // Extra slash
				}
				doubleSlashPath.WriteString(segments[j])
				if j < len(segments)-1 && segments[j] != "" {
					doubleSlashPath.WriteString("/")
				}
			}

			addJob(doubleSlashPath.String() + query)
		}

		// All slashes doubled
		var allDoubleSlashPath strings.Builder
		allDoubleSlashPath.WriteString("/")
		for j := 1; j < len(segments); j++ {
			if segments[j] != "" {
				allDoubleSlashPath.WriteString("/") // Extra slash
				allDoubleSlashPath.WriteString(segments[j])
				if j < len(segments)-1 {
					allDoubleSlashPath.WriteString("/")
				}
			}
		}

		addJob(allDoubleSlashPath.String() + query)
	}

	// --- 2. Unicode path character variations ---

	// 2.1 Find all characters in the path
	uniqueChars := make(map[int]bool)
	for _, r := range path {
		// Only handle ASCII chars that have Unicode mappings
		if r <= 127 {
			if mappings, exists := asciiToMappings[int(r)]; exists && len(mappings) > 0 {
				uniqueChars[int(r)] = true
			}
		}
	}

	// 2.2 For each unique character in the path
	for charCode := range uniqueChars {
		mappings := asciiToMappings[charCode]
		charStr := string(rune(charCode))

		// For each Unicode mapping of this character
		for _, mapping := range mappings {
			// Single replacement - Replace one occurrence at a time
			pathRunes := []rune(path)
			for i, r := range pathRunes {
				if int(r) == charCode {
					// Raw Unicode replacement
					rawPath := string(pathRunes[:i]) + mapping.Unicode + string(pathRunes[i+1:])
					addJob(rawPath + query)

					// URL-encoded replacement
					encodedPath := string(pathRunes[:i]) + mapping.URLEncoded + string(pathRunes[i+1:])
					addJob(encodedPath + query)

					// UTF-8 bytes replacement
					bytesPath := string(pathRunes[:i]) + mapping.UTF8Bytes + string(pathRunes[i+1:])
					addJob(bytesPath + query)
				}
			}

			// Replace all occurrences of this character
			rawAllPath := strings.ReplaceAll(path, charStr, mapping.Unicode)
			addJob(rawAllPath + query)

			encodedAllPath := strings.ReplaceAll(path, charStr, mapping.URLEncoded)
			addJob(encodedAllPath + query)

			bytesAllPath := strings.ReplaceAll(path, charStr, mapping.UTF8Bytes)
			addJob(bytesAllPath + query)
		}
	}

	// --- 3. Path segment character variations ---
	if len(segments) > 1 {
		for i := 1; i < len(segments); i++ {
			segment := segments[i]
			if segment == "" {
				continue
			}

			segmentRunes := []rune(segment)

			// 3.1 First character variations
			if len(segmentRunes) > 0 {
				firstChar := segmentRunes[0]
				if mappings, exists := asciiToMappings[int(firstChar)]; exists {
					for _, mapping := range mappings {
						// Create a new path with this segment's first char replaced
						newSegment := mapping.Unicode + string(segmentRunes[1:])
						newPath := createPathWithReplacedSegment(segments, i, newSegment)
						addJob(newPath + query)

						// URL-encoded version
						encodedSegment := mapping.URLEncoded + string(segmentRunes[1:])
						encodedPath := createPathWithReplacedSegment(segments, i, encodedSegment)
						addJob(encodedPath + query)

						// UTF-8 bytes version
						bytesSegment := mapping.UTF8Bytes + string(segmentRunes[1:])
						bytesPath := createPathWithReplacedSegment(segments, i, bytesSegment)
						addJob(bytesPath + query)
					}
				}
			}

			// 3.2 Last character variations
			if len(segmentRunes) > 1 {
				lastChar := segmentRunes[len(segmentRunes)-1]
				if mappings, exists := asciiToMappings[int(lastChar)]; exists {
					for _, mapping := range mappings {
						// Create a new path with this segment's last char replaced
						newSegment := string(segmentRunes[:len(segmentRunes)-1]) + mapping.Unicode
						newPath := createPathWithReplacedSegment(segments, i, newSegment)
						addJob(newPath + query)

						// URL-encoded version
						encodedSegment := string(segmentRunes[:len(segmentRunes)-1]) + mapping.URLEncoded
						encodedPath := createPathWithReplacedSegment(segments, i, encodedSegment)
						addJob(encodedPath + query)

						// UTF-8 bytes version
						bytesSegment := string(segmentRunes[:len(segmentRunes)-1]) + mapping.UTF8Bytes
						bytesPath := createPathWithReplacedSegment(segments, i, bytesSegment)
						addJob(bytesPath + query)
					}
				}
			}

			// 3.3 Every character in the segment
			for j, char := range segmentRunes {
				if mappings, exists := asciiToMappings[int(char)]; exists {
					// Take just a few mappings to avoid explosion
					maxMappings := 3
					if len(mappings) < maxMappings {
						maxMappings = len(mappings)
					}

					for k := 0; k < maxMappings; k++ {
						mapping := mappings[k]

						// Create segment with this character replaced
						newRunes := make([]rune, len(segmentRunes))
						copy(newRunes, segmentRunes)
						newRunes[j] = []rune(mapping.Unicode)[0]

						newSegment := string(newRunes)
						newPath := createPathWithReplacedSegment(segments, i, newSegment)
						addJob(newPath + query)
					}
				}
			}
		}
	}

	// --- 4. Special case: Unicode insertions ---
	// Get slash mappings specifically
	slashMappings, exists := asciiToMappings[47] // '/'
	if exists && len(slashMappings) > 0 {
		// Limit to a few mappings to prevent explosion
		maxMappings := 3
		if len(slashMappings) < maxMappings {
			maxMappings = len(slashMappings)
		}

		for i := 0; i < maxMappings; i++ {
			mapping := slashMappings[i]

			// Insert Unicode slash after each real slash
			pathRunes := []rune(path)
			for j := 0; j < len(pathRunes); j++ {
				if pathRunes[j] == '/' {
					// Raw Unicode insertion
					insertPath := string(pathRunes[:j+1]) + mapping.Unicode + string(pathRunes[j+1:])
					addJob(insertPath + query)

					// URL-encoded insertion
					encodedPath := string(pathRunes[:j+1]) + mapping.URLEncoded + string(pathRunes[j+1:])
					addJob(encodedPath + query)

					// UTF-8 bytes insertion
					bytesPath := string(pathRunes[:j+1]) + mapping.UTF8Bytes + string(pathRunes[j+1:])
					addJob(bytesPath + query)
				}
			}
		}
	}

	GB403Logger.Debug().BypassModule(bypassModule).
		Msgf("Generated %d unicode normalization payloads for %s", len(jobs), targetURL)
	return jobs
}

// Helper function to create a path with a replaced segment
func createPathWithReplacedSegment(segments []string, index int, newSegment string) string {
	var newPath strings.Builder
	newPath.WriteString("/")

	for i := 1; i < len(segments); i++ {
		if i == index {
			newPath.WriteString(newSegment)
		} else {
			newPath.WriteString(segments[i])
		}

		if i < len(segments)-1 && segments[i] != "" {
			newPath.WriteString("/")
		}
	}

	return newPath.String()
}

/**
JS code used to fuzz unicode path chars

const charsToCheck = ["\\", "/", ".", ":", "%", "~", "*", "<", ">", "|", "@", "!", "#", "+", "{", "}", "[", "]", ";", ",", "'", "\""];
const normalizationForms = ["NFKC", "NFC", "NFD", "NFKD"];

const normalizedMatches = new Set();

// Loop through all code points (from 0x7f upwards)

	for (let i = 0x7f; i <= 0x10FFFF; i++) {
	    const char = String.fromCodePoint(i);

	    if (i > 0x7f) {
	        normalizationForms.forEach(form => {
	            const normalized = char.normalize(form);

	            for (let charToCheck of charsToCheck) {
	                if (charToCheck === normalized) {
	                    normalizedMatches.add(`${char}(${form})=${charToCheck}`);
	                }
	            }
	        });
	    }
	}

normalizedMatches.forEach(match => console.log(match));
**/
