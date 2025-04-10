package payload

import (
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

func (pg *PayloadGenerator) GenerateCaseSubstitutionPayloads(targetURL string, bypassModule string) []BypassPayload {
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

	// map[rawURI]struct{} - we only need unique RawURIs
	uniquePaths := make(map[string]struct{})

	// Base job template
	baseJob := BypassPayload{
		OriginalURL:  targetURL,
		Method:       "GET",
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		BypassModule: bypassModule,
	}

	// 1. CAIDO TECHNIQUE: Last letter uppercase
	if len(basePath) > 0 {
		lastCharIndex := len(basePath) - 1
		lastChar := basePath[lastCharIndex]

		if isLetter(byte(lastChar)) && lastChar >= 'a' && lastChar <= 'z' {
			// Create version with just the last letter uppercase
			lastLetterUppercase := basePath[:lastCharIndex] + strings.ToUpper(string(lastChar))
			uniquePaths[lastLetterUppercase+query] = struct{}{}
		}
	}

	// 2. First line (method) uppercase
	// Create a variant with uppercase method
	methodUpperJob := baseJob
	methodUpperJob.Method = strings.ToUpper(methodUpperJob.Method) // Already uppercase for GET but handles other methods
	methodUpperJob.RawURI = basePath + query
	methodUpperJob.PayloadToken = GeneratePayloadToken(methodUpperJob)
	allJobs = append(allJobs, methodUpperJob)

	// 3. Find and invert case for all letter positions
	for i, char := range basePath {
		if isLetter(byte(char)) {
			// Create case-inverted version
			newPath := basePath[:i]
			if char >= 'a' && char <= 'z' {
				newPath += strings.ToUpper(string(char))
			} else {
				newPath += strings.ToLower(string(char))
			}
			newPath += basePath[i+1:]

			// Add query to the case-modified path
			uniquePaths[newPath+query] = struct{}{}
		}
	}

	// Convert unique paths to PayloadJobs
	for rawURI := range uniquePaths {
		job := baseJob
		job.RawURI = rawURI
		job.PayloadToken = GeneratePayloadToken(job)
		allJobs = append(allJobs, job)
	}

	// 4. Full uppercase path (this is more comprehensive than Caido's approach)
	fullUpperPath := strings.ToUpper(basePath)
	if fullUpperPath != basePath { // Only if there's something to change
		job := baseJob
		job.RawURI = fullUpperPath + query
		job.PayloadToken = GeneratePayloadToken(job)
		allJobs = append(allJobs, job)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(allJobs), targetURL)
	return allJobs
}
