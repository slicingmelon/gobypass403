package main

import (
	"encoding/json"
	"fmt"
	"os"
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
func getReadableASCII(r rune) string {
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
		if r < 32 || r == 127 {
			return fmt.Sprintf("\\x%02X", r) // other control chars
		}
		return string(r) // printable chars
	}
}

// GenerateFullCharMap generates a mapping for all ASCII characters (0-127)
// and checks Unicode characters that normalize to them
func GenerateFullCharMap() ([]OrderedCharMap, error) {
	// Initialize a temporary map
	tempMap := make(map[int][]UnicodeMapping)

	// Initialize with all ASCII characters (0-127)
	for r := 0; r <= 127; r++ {
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

	// Check all Unicode characters up to 0xFFFF (can extend to 0x10FFFF if needed)
	for r := rune(0x80); r <= 0xFFFF; r++ {
		// Skip control characters in the unicode range (but we will still map TO control chars)
		if unicode.IsControl(r) {
			continue
		}

		char := string(r)

		// Try each normalization form
		for _, n := range normForms {
			normalized := n.form.String(char)

			// If the character normalizes to a single ASCII character
			if len(normalized) == 1 && normalized[0] <= 127 {
				// Get ASCII value of normalized char
				asciiVal := int(normalized[0])

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
				tempMap[asciiVal] = append(tempMap[asciiVal], UnicodeMapping{
					Unicode:         char,
					UTF8Bytes:       bytesRepr.String(),
					URLEncoded:      urlEncoded.String(),
					NormalizeAs:     getReadableASCII(rune(asciiVal)),
					NormalizesAsHex: fmt.Sprintf("\\x%02X", asciiVal),
					Form:            n.name,
				})

				break
			}
		}
	}

	// Convert to ordered slice
	result := make([]OrderedCharMap, 128)
	for i := 0; i <= 127; i++ {
		result[i] = OrderedCharMap{
			ASCII:    i,
			Char:     getReadableASCII(rune(i)),
			Mappings: tempMap[i],
		}
	}

	return result, nil
}

func main() {
	fmt.Println("Generating Unicode mappings for all ASCII characters (0-127)...")

	charMap, err := GenerateFullCharMap()
	if err != nil {
		fmt.Printf("Error generating character map: %v\n", err)
		os.Exit(1)
	}

	// Save to a fixed file name
	outputFile := "unicode_char_map.json"

	data, err := json.MarshalIndent(charMap, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(outputFile, data, 0644); err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
		os.Exit(1)
	}

	// Print some stats
	totalMappings := 0
	for _, entry := range charMap {
		totalMappings += len(entry.Mappings)
	}

	fmt.Printf("Completed successfully! Found %d Unicode characters that normalize to ASCII\n", totalMappings)
	fmt.Printf("Results saved to %s\n", outputFile)
}
