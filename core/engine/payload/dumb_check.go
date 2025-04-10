package payload

import (
	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

func (pg *PayloadGenerator) GenerateDumbCheckPayload(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
		return allJobs
	}

	// Extract path and query
	rawURI := parsedURL.Path
	if parsedURL.Query != "" {
		rawURI += "?" + parsedURL.Query
	}

	// Just one job with the original URL
	job := BypassPayload{
		OriginalURL:  targetURL,
		Method:       "GET",
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		RawURI:       rawURI,
		BypassModule: bypassModule,
	}

	// Generate token with only the necessary components
	job.PayloadToken = GeneratePayloadToken(job)

	allJobs = append(allJobs, job)

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated 1 payload for %s\n", targetURL)
	return allJobs
}
