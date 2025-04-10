package payload

import (
	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

/*
GenerateHeaderPortPayloads
*/
func (pg *PayloadGenerator) GenerateHeaderPortPayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
		return allJobs
	}

	headerPorts, err := ReadPayloadsFromFile("header_ports.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read header ports: %v", err)
		return allJobs
	}

	internalPorts, err := ReadPayloadsFromFile("internal_ports.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read internal ports: %v", err)
		return allJobs
	}

	// Extract path and query
	rawURI := parsedURL.Path
	if parsedURL.Query != "" {
		rawURI += "?" + parsedURL.Query
	}

	// Base job template
	baseJob := BypassPayload{
		OriginalURL:  targetURL,
		Method:       "GET",
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		RawURI:       rawURI,
		BypassModule: bypassModule,
	}

	for _, headerPort := range headerPorts {
		if headerPort == "" {
			continue
		}

		// Handle internal ports
		for _, port := range internalPorts {
			job := baseJob
			job.Headers = []Headers{{
				Header: headerPort,
				Value:  port,
			}}
			job.PayloadToken = GeneratePayloadToken(job)
			allJobs = append(allJobs, job)
		}
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(allJobs), targetURL)
	return allJobs
}
