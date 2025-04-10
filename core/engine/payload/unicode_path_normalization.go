package payload

import (
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

/*
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
/----------------------------------------------------------/
GenerateUnicodePathNormalizationsPayloads
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

	// Read Unicode mappings
	unicodeMappings, err := ReadPayloadsFromFile("unicode_path_chars.lst")
	if err != nil {
		GB403Logger.Error().BypassModule(bypassModule).Msgf("Failed to read unicode_path_chars.lst: %v", err)
		return jobs
	}

	// Build character mapping: ASCII char -> list of Unicode variant strings
	targetChars := map[rune]bool{'.': true, '/': true}
	// charMap stores: ASCII rune -> list of Unicode variant strings
	charMap := make(map[rune][]string)
	// Store variants specifically for '/' to avoid hardcoding later
	slashUnicodeVariants := []string{}

	for _, mapping := range unicodeMappings {
		parts := strings.SplitN(mapping, "=", 2) // Use SplitN for safety
		if len(parts) != 2 {
			GB403Logger.Warning().BypassModule(bypassModule).Msgf("Skipping malformed line in unicode_path_chars.lst: %s", mapping)
			continue
		}

		// parts[0] contains the Unicode char + normalization info like "／(NFKC)"
		// parts[1] contains the ASCII char like "/"
		asciiStr := parts[1]
		if len(asciiStr) == 0 {
			continue // Skip if ASCII part is empty
		}
		asciiChar := []rune(asciiStr)[0] // Get the first rune of the ASCII string

		// Check if this ASCII char is one we care about ('.' or '/')
		if !targetChars[asciiChar] {
			continue
		}

		// Extract only the Unicode character part from parts[0]
		unicodeChar := strings.SplitN(parts[0], "(", 2)[0]
		if unicodeChar == "" {
			continue // Skip if Unicode part is empty
		}

		// Add to the general map
		charMap[asciiChar] = append(charMap[asciiChar], unicodeChar)

		// If it's a variant for '/', store it separately too
		if asciiChar == '/' {
			slashUnicodeVariants = append(slashUnicodeVariants, unicodeChar)
		}
	}

	if len(charMap) == 0 {
		GB403Logger.Warning().BypassModule(bypassModule).Msgf("No usable mappings found for '.' or '/' in unicode_path_chars.lst")
		return jobs
	}
	if len(slashUnicodeVariants) == 0 {
		GB403Logger.Warning().BypassModule(bypassModule).Msgf("No Unicode variants found for '/' in unicode_path_chars.lst for structural tests")
		// Proceeding without structural tests might still be useful
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
			job.PayloadToken = GeneratePayloadToken(job) // Assuming this generates a unique token
			jobs = append(jobs, job)
		}
	}

	// Helper to add both Unicode and URL-encoded path variants if they are unique
	addPathVariants := func(unicodePath, encodedPath string) {
		addJob(unicodePath + query)
		addJob(encodedPath + query)
	}

	// --- Payload Generation Logic ---

	// 1. Single character replacements
	pathRunes := []rune(path) // Work with runes for correct Unicode indexing
	for i, currentRune := range pathRunes {
		if unicodeVariants, found := charMap[currentRune]; found {
			for _, unicodeVariant := range unicodeVariants {
				// Create Unicode version
				tempRunes := make([]rune, len(pathRunes))
				copy(tempRunes, pathRunes)
				tempRunes[i] = []rune(unicodeVariant)[0] // Replace with the first rune of the variant
				unicodePath := string(tempRunes)

				// Create URL-encoded version
				encodedVariant := URLEncodeAll(unicodeVariant) // Encode the full variant string
				encodedPath := string(pathRunes[:i]) + encodedVariant + string(pathRunes[i+1:])

				addPathVariants(unicodePath, encodedPath)
			}
		}
	}

	// 2. Replace all occurrences of each target character
	for targetChar, variants := range charMap {
		targetStr := string(targetChar) // The character to replace (e.g., ".", "/")
		for _, unicodeVariant := range variants {
			// Replace all with Unicode variant
			unicodePath := strings.ReplaceAll(path, targetStr, unicodeVariant)

			// Replace all with URL-encoded variant (needs careful construction)
			var encodedPathBuilder strings.Builder
			encodedVariant := URLEncodeAll(unicodeVariant)
			lastIndex := 0
			for i := strings.Index(path[lastIndex:], targetStr); i != -1; i = strings.Index(path[lastIndex:], targetStr) {
				currentIndex := lastIndex + i
				encodedPathBuilder.WriteString(path[lastIndex:currentIndex]) // Part before the match
				encodedPathBuilder.WriteString(encodedVariant)               // Encoded replacement
				lastIndex = currentIndex + len(targetStr)                    // Move past the replaced character
			}
			encodedPathBuilder.WriteString(path[lastIndex:]) // Add any remaining part
			encodedPath := encodedPathBuilder.String()

			addPathVariants(unicodePath, encodedPath)
		}
	}

	// 3. Special case: Add Unicode slash variant before the last segment
	//    (Only if slash variants were found)
	if len(slashUnicodeVariants) > 0 {
		segments := strings.Split(path, "/")
		// Handle paths like "/a/b/" vs "/a/b" correctly. Need >2 segments for structure like "/a/VARb"
		// If path ends with /, last segment is "", need len > 2.
		// If path doesn't end with /, last segment is "b", need len > 1.
		meaningfulSegments := len(segments)
		if meaningfulSegments > 0 && segments[meaningfulSegments-1] == "" {
			meaningfulSegments-- // Adjust if path ends with a slash
		}

		if meaningfulSegments > 1 {
			lastSegmentIndex := len(segments) - 1
			if segments[lastSegmentIndex] == "" { // Handle trailing slash case
				lastSegmentIndex--
			}
			lastSegment := segments[lastSegmentIndex]

			prefix := strings.Join(segments[:lastSegmentIndex], "/")

			for _, slashVariant := range slashUnicodeVariants {
				// Unicode variant before last segment
				unicodePath := prefix + "/" + slashVariant + lastSegment
				// Encoded variant before last segment
				encodedPath := prefix + "/" + URLEncodeAll(slashVariant) + lastSegment

				addPathVariants(unicodePath, encodedPath)
			}
		}
	}

	// 4. Enhanced technique: Add Unicode slash variants after each existing slash
	//    (Only if slash variants were found)
	if len(slashUnicodeVariants) > 0 && strings.Contains(path, "/") {
		pathRunes := []rune(path)
		for i, currentRune := range pathRunes {
			if currentRune == '/' {
				// For each variant, create paths with variant inserted after this slash
				for _, slashVariant := range slashUnicodeVariants {
					// Path with raw Unicode variant inserted
					unicodePath := string(pathRunes[:i+1]) + slashVariant + string(pathRunes[i+1:])

					// Path with URL-encoded variant inserted
					encodedPath := string(pathRunes[:i+1]) + URLEncodeAll(slashVariant) + string(pathRunes[i+1:])

					addPathVariants(unicodePath, encodedPath)
				}
			}
		}
	}

	GB403Logger.Debug().BypassModule(bypassModule).
		Msgf("Generated %d unicode normalization payloads for %s", len(jobs), targetURL)
	return jobs
}
