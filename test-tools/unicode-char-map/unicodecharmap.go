package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

type UnicodeMapping struct {
	Unicode         string `json:"unicode"`
	UTF8Bytes       string `json:"utf8_bytes"`
	URLEncoded      string `json:"url_encoded"`
	NormalizeAs     string `json:"normalizes_as"`
	NormalizesAsHex string `json:"normalizes_as_hex"`
	Form            string `json:"form"`
}

// An ordered map representation
type OrderedCharMap struct {
	ASCII    int              `json:"ascii"`
	Char     string           `json:"char"`
	Mappings []UnicodeMapping `json:"mappings"`
}

// Helper function to get readable representation of control characters
func getReadableChar(r rune) string {
	switch r {
	case 0:
		return "\\0" // null
	case 9:
		return "\\t" // tab
	case 10:
		return "\\n" // line feed
	case 13:
		return "\\r" // carriage return
	default:
		// Check for C0 and C1 control characters and other non-printable runes
		if unicode.IsControl(r) || !unicode.IsPrint(r) {
			if r <= 0xFF {
				return fmt.Sprintf("\\x%02X", r)
			}
			return fmt.Sprintf("\\u%04X", r)
		}
		return string(r) // printable chars
	}
}

// GenerateTruncationMap generates mappings for characters that truncate to target range
// by taking the low byte (char & 0xFF) and checking if it falls within the target range.
func GenerateTruncationMap(min, max, maxTrunc int) ([]OrderedCharMap, error) {
	// Initialize a temporary map
	tempMap := make(map[int][]UnicodeMapping)

	// Initialize with all characters in the target range
	for r := min; r <= max; r++ {
		tempMap[r] = []UnicodeMapping{}
	}

	// Check all Unicode characters up to 0x10FFFF
	for r := rune(0); r <= 0x10FFFF; r++ {
		// Skip surrogate pairs as they are not valid standalone characters.
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}

		lowByte := int(r & 0xFF) // Get low byte
		if lowByte >= min && lowByte <= max && r != rune(lowByte) {
			// Check if we've reached the max truncation limit for this character.
			if maxTrunc > 0 && len(tempMap[lowByte]) >= maxTrunc {
				continue // Skip if we already have enough mappings.
			}

			char := string(r)

			// Create UTF-8 bytes representation
			var bytesRepr strings.Builder
			for _, b := range []byte(char) {
				bytesRepr.WriteString(fmt.Sprintf("\\x%02X", b))
			}

			// Create URL-encoded representation
			var urlEncoded strings.Builder
			for _, b := range []byte(char) {
				urlEncoded.WriteString(fmt.Sprintf("%%%02X", b))
			}

			// Add to map
			tempMap[lowByte] = append(tempMap[lowByte], UnicodeMapping{
				Unicode:         char,
				UTF8Bytes:       bytesRepr.String(),
				URLEncoded:      urlEncoded.String(),
				NormalizeAs:     getReadableChar(rune(lowByte)),
				NormalizesAsHex: fmt.Sprintf("\\x%02X", lowByte),
				Form:            "TRUNCATION",
			})
		}
	}

	// Convert to ordered slice, including entries without mappings
	result := make([]OrderedCharMap, 0, max-min+1)
	for i := min; i <= max; i++ {
		result = append(result, OrderedCharMap{
			ASCII:    i,
			Char:     getReadableChar(rune(i)),
			Mappings: tempMap[i],
		})
	}

	return result, nil
}

// GenerateCharMap generates a mapping for a given character range
// and checks Unicode characters that normalize to them.
func GenerateCharMap(min, max, maxNorms int) ([]OrderedCharMap, error) {
	// Initialize a temporary map
	tempMap := make(map[int][]UnicodeMapping)

	// Initialize with all characters in the target range
	for r := min; r <= max; r++ {
		tempMap[r] = []UnicodeMapping{}
	}

	normForms := []struct {
		form norm.Form
		name string
	}{
		{norm.NFKC, "NFKC"},
		{norm.NFKD, "NFKD"},
		{norm.NFC, "NFC"},
		{norm.NFD, "NFD"},
	}

	// Check all Unicode characters up to 0x10FFFF
	for r := rune(0); r <= 0x10FFFF; r++ {
		// Skip surrogate pairs as they are not valid standalone characters.
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}

		// Skip control characters in the Unicode range, as they are not typically user-input.
		if unicode.IsControl(r) {
			continue
		}

		char := string(r)

		// Try each normalization form
		for _, n := range normForms {
			normalized := n.form.String(char)

			// If the character normalizes to a single character within our target range
			if len(normalized) == 1 {
				normVal := int(rune(normalized[0]))
				if normVal >= min && normVal <= max {
					// Check if we've reached the max norms limit for this character.
					if maxNorms > 0 && len(tempMap[normVal]) >= maxNorms {
						continue // Skip if we already have enough mappings.
					}

					// Create UTF-8 bytes representation
					var bytesRepr strings.Builder
					for _, b := range []byte(char) {
						bytesRepr.WriteString(fmt.Sprintf("\\x%02X", b))
					}

					// Create URL-encoded representation
					var urlEncoded strings.Builder
					for _, b := range []byte(char) {
						urlEncoded.WriteString(fmt.Sprintf("%%%02X", b))
					}

					// Add to map
					tempMap[normVal] = append(tempMap[normVal], UnicodeMapping{
						Unicode:         char,
						UTF8Bytes:       bytesRepr.String(),
						URLEncoded:      urlEncoded.String(),
						NormalizeAs:     getReadableChar(rune(normVal)),
						NormalizesAsHex: fmt.Sprintf("\\x%02X", normVal),
						Form:            n.name,
					})

					break // Found a normalization, move to the next Unicode character.
				}
			}
		}
	}

	// Convert to ordered slice, including entries without mappings
	result := make([]OrderedCharMap, 0, max-min+1)
	for i := min; i <= max; i++ {
		result = append(result, OrderedCharMap{
			ASCII:    i,
			Char:     getReadableChar(rune(i)),
			Mappings: tempMap[i],
		})
	}

	return result, nil
}

// mergeCharMaps merges two character maps, combining mappings for each ASCII character
func mergeCharMaps(map1, map2 []OrderedCharMap) []OrderedCharMap {
	// Create a lookup map for efficient merging
	mergedMap := make(map[int]*OrderedCharMap)

	// Add first map
	for _, entry := range map1 {
		mergedMap[entry.ASCII] = &OrderedCharMap{
			ASCII:    entry.ASCII,
			Char:     entry.Char,
			Mappings: make([]UnicodeMapping, len(entry.Mappings)),
		}
		copy(mergedMap[entry.ASCII].Mappings, entry.Mappings)
	}

	// Merge second map
	for _, entry := range map2 {
		if existing, exists := mergedMap[entry.ASCII]; exists {
			existing.Mappings = append(existing.Mappings, entry.Mappings...)
		} else {
			mergedMap[entry.ASCII] = &OrderedCharMap{
				ASCII:    entry.ASCII,
				Char:     entry.Char,
				Mappings: make([]UnicodeMapping, len(entry.Mappings)),
			}
			copy(mergedMap[entry.ASCII].Mappings, entry.Mappings)
		}
	}

	// Convert back to ordered slice and find min/max bounds
	minKey, maxKey := 0, 0
	first := true
	for key := range mergedMap {
		if first || key < minKey {
			minKey = key
		}
		if first || key > maxKey {
			maxKey = key
		}
		first = false
	}

	result := make([]OrderedCharMap, 0, len(mergedMap))
	for i := minKey; i <= maxKey; i++ {
		if entry, exists := mergedMap[i]; exists {
			result = append(result, *entry)
		}
	}

	return result
}

func main() {
	// Define flags
	rangeStr := flag.String("range", "0-127", "The target character range to generate mappings for (e.g., '0-255').")
	maxNorms := flag.Int("max-norms", 0, "Maximum number of normalization mappings per character (0 for unlimited).")
	includeTruncation := flag.Bool("include-truncation", false, "Include truncation mappings in addition to normalization mappings.")
	maxTrunc := flag.Int("max-trunc", 0, "Maximum number of truncation mappings per character (0 for unlimited).")
	outputFile := flag.String("output", "unicode_char_map.json", "Output file name for the JSON map.")
	flag.Parse()

	// Declare variables
	var charMap []OrderedCharMap
	var err error
	var min, max int

	// Parse range string
	parts := strings.Split(*rangeStr, "-")
	if len(parts) != 2 {
		fmt.Fprintln(os.Stderr, "Error: Invalid range format. Please use 'min-max'.")
		os.Exit(1)
	}

	min, err = strconv.Atoi(parts[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing min value from range: %v\n", err)
		os.Exit(1)
	}

	max, err = strconv.Atoi(parts[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing max value from range: %v\n", err)
		os.Exit(1)
	}

	if min < 0 || max < 0 || min > max {
		fmt.Fprintln(os.Stderr, "Error: Invalid range values. Min and max must be non-negative, and min must be <= max.")
		os.Exit(1)
	}

	fmt.Printf("Generating Unicode mappings for character range %d-%d...\n", min, max)
	if *maxNorms > 0 {
		fmt.Printf("Limiting to a maximum of %d normalization mappings per character.\n", *maxNorms)
	}
	if *includeTruncation && *maxTrunc > 0 {
		fmt.Printf("Limiting to a maximum of %d truncation mappings per character.\n", *maxTrunc)
	}

	if *includeTruncation {
		fmt.Println("Generating normalization mappings...")
		normMap, err2 := GenerateCharMap(min, max, *maxNorms)
		if err2 != nil {
			fmt.Fprintf(os.Stderr, "Error generating normalization character map: %v\n", err2)
			os.Exit(1)
		}

		fmt.Println("Generating truncation mappings...")
		truncMap, err3 := GenerateTruncationMap(min, max, *maxTrunc)
		if err3 != nil {
			fmt.Fprintf(os.Stderr, "Error generating truncation character map: %v\n", err3)
			os.Exit(1)
		}

		fmt.Println("Merging mappings...")
		charMap = mergeCharMaps(normMap, truncMap)
	} else {
		charMap, err = GenerateCharMap(min, max, *maxNorms)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating character map: %v\n", err)
			os.Exit(1)
		}
	}

	data, err := json.MarshalIndent(charMap, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*outputFile, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
		os.Exit(1)
	}

	// Print some stats
	totalMappings := 0
	normalizationMappings := 0
	truncationMappings := 0

	for _, entry := range charMap {
		for _, mapping := range entry.Mappings {
			totalMappings++
			if mapping.Form == "TRUNCATION" {
				truncationMappings++
			} else {
				normalizationMappings++
			}
		}
	}

	fmt.Printf("Completed successfully! Found %d total Unicode character mappings:\n", totalMappings)
	if normalizationMappings > 0 {
		fmt.Printf("  - %d normalization mappings\n", normalizationMappings)
	}
	if truncationMappings > 0 {
		fmt.Printf("  - %d truncation mappings\n", truncationMappings)
	}
	fmt.Printf("Results saved to %s\n", *outputFile)
}
