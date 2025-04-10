package payload

import (
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

/*
GenerateEndPathsPayloads
*/
func (pg *PayloadGenerator) GenerateEndPathsPayloads(targetURL string, bypassModule string) []BypassPayload {
	var jobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
		return jobs
	}

	payloads, err := ReadPayloadsFromFile("internal_endpaths.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read endpaths payloads: %v\n", err)
		return jobs
	}

	basePath := parsedURL.Path
	separator := ""
	if basePath != "/" && !strings.HasSuffix(basePath, "/") {
		separator = "/"
	}

	// Extract query string if it exists
	query := ""
	if parsedURL.Query != "" {
		query = "?" + parsedURL.Query
	}

	// map[rawURI]struct{} - we only need unique RawURIs
	uniquePaths := make(map[string]struct{})

	for _, payload := range payloads {
		// First variant - 'url/suffix'
		rawURI := basePath + separator + payload + query
		uniquePaths[rawURI] = struct{}{}

		// Second variant - 'url/suffix/'
		rawURIWithSlash := basePath + separator + payload + "/" + query
		uniquePaths[rawURIWithSlash] = struct{}{}

		// Only if basePath is not "/" and payload doesn't start with a letter
		if basePath != "/" {
			if !isLetter(payload[0]) {
				// Third variant - Add 'suffix'
				rawURISuffix := basePath + payload + query
				uniquePaths[rawURISuffix] = struct{}{}

				// Fourth variant - Add 'suffix/'
				rawURISuffixSlash := basePath + payload + "/" + query
				uniquePaths[rawURISuffixSlash] = struct{}{}
			}
		}
	}

	// Convert unique paths to PayloadJobs
	for rawURI := range uniquePaths {
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

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(jobs), targetURL)
	return jobs
}
