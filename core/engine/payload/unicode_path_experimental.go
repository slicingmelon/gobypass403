package payload

import (
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

// SubstituteWithUnicodeLookalikes replaces standard characters in a payload string
// with their primary Unicode lookalikes, based on the provided character map.
// It avoids replacing characters that are part of a percent-encoded sequence.
func SubstituteWithUnicodeLookalikes(payload string, charMap map[rune]string) string {
	var builder strings.Builder
	builder.Grow(len(payload) * 2) // Pre-allocate, assuming some chars will expand
	runes := []rune(payload)
	i := 0
	for i < len(runes) {
		// Check for percent-encoding pattern (e.g., %2f)
		if runes[i] == '%' && i+2 < len(runes) {
			// Check if the next two characters are valid hex digits.
			// This is a simplified check; a more robust one might be needed
			// if payloads can contain malformed percent-encodings.
			if (runes[i+1] >= '0' && runes[i+1] <= '9') || (runes[i+1] >= 'a' && runes[i+1] <= 'f') || (runes[i+1] >= 'A' && runes[i+1] <= 'F') {
				if (runes[i+2] >= '0' && runes[i+2] <= '9') || (runes[i+2] >= 'a' && runes[i+2] <= 'f') || (runes[i+2] >= 'A' && runes[i+2] <= 'F') {
					// It's a percent-encoded sequence, keep it as is.
					builder.WriteRune(runes[i])
					builder.WriteRune(runes[i+1])
					builder.WriteRune(runes[i+2])
					i += 3
					continue
				}
			}
		}

		// Not a percent-encoded sequence, check for substitution
		if replacement, ok := charMap[runes[i]]; ok {
			builder.WriteString(replacement)
		} else {
			builder.WriteRune(runes[i])
		}
		i++
	}
	return builder.String()
}

/*
GenerateUnicodePathExperimentalPayloads generates payloads by first substituting characters in the
mid_paths list with their Unicode lookalikes and then applying the same generation logic
as the standard `mid_paths` module.
*/
func (pg *PayloadGenerator) GenerateUnicodePathExperimentalPayloads(targetURL string, bypassModule string) []BypassPayload {
	// 1. Load the Unicode character map for substitutions.
	unicodeMap, err := ReadUnicodeCharMap()
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read unicode_char_map.json for experimental module: %v", err)
		return []BypassPayload{}
	}

	// Create an efficient lookup map (rune -> primary unicode lookalike)
	charToUnicode := make(map[rune]string)
	for _, entry := range unicodeMap {
		if len(entry.Mappings) > 0 {
			// Use the first mapping as the primary lookalike
			charToUnicode[[]rune(entry.Char)[0]] = entry.Mappings[0].Unicode
		}
	}

	// 2. Read the raw midpath payloads from the file.
	rawPayloads, err := ReadPayloadsFromFile("internal_midpaths.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read midpaths payloads for experimental module: %v", err)
		return []BypassPayload{}
	}

	// 3. Create a new list of payloads with Unicode substitutions.
	unicodePayloads := make([]string, len(rawPayloads))
	for i, payload := range rawPayloads {
		unicodePayloads[i] = SubstituteWithUnicodeLookalikes(payload, charToUnicode)
	}

	// 4. Use the existing mid_paths generation logic but with the new Unicode payloads.
	// This is a temporary modification of the payload generator for this specific run.
	return pg.generateMidPathsWithCustomPayloads(targetURL, bypassModule, unicodePayloads)
}

// generateMidPathsWithCustomPayloads is a modified version of GenerateMidPathsPayloads that accepts a custom payload list.
func (pg *PayloadGenerator) generateMidPathsWithCustomPayloads(targetURL string, bypassModule string, payloads []string) []BypassPayload {
	var jobs []BypassPayload
	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL: %s", targetURL)
		return jobs
	}

	path := parsedURL.Path
	if path == "" {
		path = "/"
	}
	query := ""
	if parsedURL.Query != "" {
		query = "?" + parsedURL.Query
	}

	uniquePaths := make(map[string]struct{})
	addPathWithVariants := func(path string) {
		uniquePaths[path+query] = struct{}{}
		if strings.ContainsAny(path, "?#") {
			encodedPath := encodeQueryAndFragmentChars(path)
			uniquePaths[encodedPath+query] = struct{}{}
		}
	}

	hasLeadingSlash := strings.HasPrefix(path, "/")
	pathWithoutLeadingSlash := strings.TrimPrefix(path, "/")
	segments := strings.Split(pathWithoutLeadingSlash, "/")

	for _, payload := range payloads {
		addPathWithVariants(payload + path)
		addPathWithVariants("/" + payload + path)
		if strings.HasSuffix(payload, "/") && hasLeadingSlash {
			addPathWithVariants("/" + payload + path)
		}
	}

	if path != "/" {
		for i, segment := range segments {
			if segment == "" {
				continue
			}

			for _, payload := range payloads {
				prefix := ""
				if hasLeadingSlash {
					prefix = "/"
				}
				prefix += strings.Join(segments[:i], "/")
				if i > 0 && len(segments[:i]) > 0 && segments[i-1] != "" {
					prefix += "/"
				}

				suffix := ""
				if i+1 < len(segments) {
					suffix = "/" + strings.Join(segments[i+1:], "/")
				}

				segStartFused := prefix + payload + segment + suffix
				addPathWithVariants(segStartFused)
				addPathWithVariants("/" + strings.TrimPrefix(segStartFused, "/"))

				segEndFused := prefix + segment + payload + suffix
				addPathWithVariants(segEndFused)
				addPathWithVariants("/" + strings.TrimPrefix(segEndFused, "/"))

				if i < len(segments)-1 || suffix == "" {
					afterSlash := prefix + segment + "/" + payload + suffix
					addPathWithVariants(afterSlash)
					addPathWithVariants("/" + strings.TrimPrefix(afterSlash, "/"))
				}
			}
		}
	}

	for rawURI := range uniquePaths {
		if rawURI == query && query != "" {
			continue
		}
		job := BypassPayload{
			OriginalURL:  targetURL,
			Method:       "GET",
			Scheme:       parsedURL.Scheme,
			Host:         parsedURL.Host,
			RawURI:       rawURI,
			BypassModule: bypassModule,
		}
		job.PayloadToken = GeneratePayloadToken(job)
		jobs = append(jobs, job)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s", len(jobs), targetURL)
	return jobs
}
