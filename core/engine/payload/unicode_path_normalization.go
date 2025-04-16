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
 1. **Path Separator Variations:** Inserts Unicode variants of '/' (slash)
    throughout the path.
 2. **Segment Character Variations:** Optionally replaces the first or last character
    of each path segment with a Unicode variant that normalizes to the same character.
 3. **Double Character Insertion:** Adds duplicate slashes at strategic points.

For each technique, two variations are typically generated:
-   One using the raw Unicode character (UTF-8 bytes).
-   One using the percent-encoded representation.

Original query strings are preserved in all generated payloads.
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

	// Extract mappings for slash (ASCII 47) and dot (ASCII 46)
	var slashMappings []UnicodeMapping
	var dotMappings []UnicodeMapping

	for _, entry := range charMap {
		if entry.ASCII == 47 { // '/'
			slashMappings = entry.Mappings
		} else if entry.ASCII == 46 { // '.'
			dotMappings = entry.Mappings
		}
	}

	if len(slashMappings) == 0 && len(dotMappings) == 0 {
		GB403Logger.Warning().BypassModule(bypassModule).Msgf("No Unicode mappings found for '/' or '.' in unicode_char_map.json")
		return jobs
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

	// --- Payload Generation Logic ---

	// 1. Double-slash variations
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

	// 2. Unicode slash replacements
	for _, slashMapping := range slashMappings {
		pathRunes := []rune(path)

		// Replace each slash individually
		for i, r := range pathRunes {
			if r == '/' {
				// Create path with single Unicode slash replacement (raw)
				rawReplacementPath := string(pathRunes[:i]) + slashMapping.Unicode + string(pathRunes[i+1:])
				addJob(rawReplacementPath + query)

				// Create path with single Unicode slash replacement (URL-encoded)
				urlEncodedReplacementPath := string(pathRunes[:i]) + slashMapping.URLEncoded + string(pathRunes[i+1:])
				addJob(urlEncodedReplacementPath + query)

				// Create path with raw UTF-8 bytes
				bytesReplacementPath := string(pathRunes[:i]) + slashMapping.UTF8Bytes + string(pathRunes[i+1:])
				addJob(bytesReplacementPath + query)
			}
		}

		// Replace all slashes with Unicode variant (raw)
		rawAllReplacementPath := strings.ReplaceAll(path, "/", slashMapping.Unicode)
		addJob(rawAllReplacementPath + query)

		// Replace all slashes with Unicode variant (URL-encoded)
		urlEncodedAllReplacementPath := strings.ReplaceAll(path, "/", slashMapping.URLEncoded)
		addJob(urlEncodedAllReplacementPath + query)

		// Replace all slashes with raw UTF-8 bytes
		bytesAllReplacementPath := strings.ReplaceAll(path, "/", slashMapping.UTF8Bytes)
		addJob(bytesAllReplacementPath + query)
	}

	// 3. Unicode dot replacements
	for _, dotMapping := range dotMappings {
		pathRunes := []rune(path)

		// Replace each dot individually
		for i, r := range pathRunes {
			if r == '.' {
				// Create path with single Unicode dot replacement (raw)
				rawReplacementPath := string(pathRunes[:i]) + dotMapping.Unicode + string(pathRunes[i+1:])
				addJob(rawReplacementPath + query)

				// Create path with single Unicode dot replacement (URL-encoded)
				urlEncodedReplacementPath := string(pathRunes[:i]) + dotMapping.URLEncoded + string(pathRunes[i+1:])
				addJob(urlEncodedReplacementPath + query)

				// Create path with raw UTF-8 bytes
				bytesReplacementPath := string(pathRunes[:i]) + dotMapping.UTF8Bytes + string(pathRunes[i+1:])
				addJob(bytesReplacementPath + query)
			}
		}

		// Replace all dots with Unicode variant (raw)
		rawAllReplacementPath := strings.ReplaceAll(path, ".", dotMapping.Unicode)
		addJob(rawAllReplacementPath + query)

		// Replace all dots with Unicode variant (URL-encoded)
		urlEncodedAllReplacementPath := strings.ReplaceAll(path, ".", dotMapping.URLEncoded)
		addJob(urlEncodedAllReplacementPath + query)

		// Replace all dots with raw UTF-8 bytes
		bytesAllReplacementPath := strings.ReplaceAll(path, ".", dotMapping.UTF8Bytes)
		addJob(bytesAllReplacementPath + query)
	}

	// 4. Unicode insertions - Insert after each slash
	if len(slashMappings) > 0 {
		for _, slashMapping := range slashMappings[:1] { // Use just the first mapping to avoid explosion
			pathRunes := []rune(path)

			for i, r := range pathRunes {
				if r == '/' {
					// Insert Unicode slash after real slash (raw)
					insertRawPath := string(pathRunes[:i+1]) + slashMapping.Unicode + string(pathRunes[i+1:])
					addJob(insertRawPath + query)

					// Insert Unicode slash after real slash (URL-encoded)
					insertUrlEncodedPath := string(pathRunes[:i+1]) + slashMapping.URLEncoded + string(pathRunes[i+1:])
					addJob(insertUrlEncodedPath + query)
				}
			}
		}
	}

	// 5. First/last character in path segment variations
	if len(segments) > 1 {
		// For each non-empty segment
		for i := 1; i < len(segments); i++ {
			if segments[i] == "" {
				continue
			}

			segmentRunes := []rune(segments[i])
			if len(segmentRunes) == 0 {
				continue
			}

			// First character replacement
			firstChar := segmentRunes[0]
			firstCharAscii := int(firstChar)

			// Find mappings for this first character
			for _, entry := range charMap {
				if entry.ASCII == firstCharAscii && len(entry.Mappings) > 0 {
					// Use just the first mapping to avoid explosion
					mapping := entry.Mappings[0]

					// Create segment with first char replaced
					updatedSegment := mapping.Unicode + string(segmentRunes[1:])

					// Build full path with this segment replaced
					var newPath strings.Builder
					newPath.WriteString("/")
					for j := 1; j < len(segments); j++ {
						if j == i {
							newPath.WriteString(updatedSegment)
						} else {
							newPath.WriteString(segments[j])
						}
						if j < len(segments)-1 && segments[j] != "" {
							newPath.WriteString("/")
						}
					}

					addJob(newPath.String() + query)

					// URL-encoded version
					encodedSegment := mapping.URLEncoded + string(segmentRunes[1:])
					var encodedPath strings.Builder
					encodedPath.WriteString("/")
					for j := 1; j < len(segments); j++ {
						if j == i {
							encodedPath.WriteString(encodedSegment)
						} else {
							encodedPath.WriteString(segments[j])
						}
						if j < len(segments)-1 && segments[j] != "" {
							encodedPath.WriteString("/")
						}
					}

					addJob(encodedPath.String() + query)

					// Only do one per segment to avoid explosion
					break
				}
			}

			// Last character replacement (if segment has more than one character)
			if len(segmentRunes) > 1 {
				lastChar := segmentRunes[len(segmentRunes)-1]
				lastCharAscii := int(lastChar)

				// Find mappings for this last character
				for _, entry := range charMap {
					if entry.ASCII == lastCharAscii && len(entry.Mappings) > 0 {
						// Use just the first mapping to avoid explosion
						mapping := entry.Mappings[0]

						// Create segment with last char replaced
						updatedSegment := string(segmentRunes[:len(segmentRunes)-1]) + mapping.Unicode

						// Build full path with this segment replaced
						var newPath strings.Builder
						newPath.WriteString("/")
						for j := 1; j < len(segments); j++ {
							if j == i {
								newPath.WriteString(updatedSegment)
							} else {
								newPath.WriteString(segments[j])
							}
							if j < len(segments)-1 && segments[j] != "" {
								newPath.WriteString("/")
							}
						}

						addJob(newPath.String() + query)

						// URL-encoded version
						encodedSegment := string(segmentRunes[:len(segmentRunes)-1]) + mapping.URLEncoded
						var encodedPath strings.Builder
						encodedPath.WriteString("/")
						for j := 1; j < len(segments); j++ {
							if j == i {
								encodedPath.WriteString(encodedSegment)
							} else {
								encodedPath.WriteString(segments[j])
							}
							if j < len(segments)-1 && segments[j] != "" {
								encodedPath.WriteString("/")
							}
						}

						addJob(encodedPath.String() + query)

						// Only do one per segment to avoid explosion
						break
					}
				}
			}
		}
	}

	GB403Logger.Debug().BypassModule(bypassModule).
		Msgf("Generated %d unicode normalization payloads for %s", len(jobs), targetURL)
	return jobs
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
