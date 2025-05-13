package payload

import (
	"fmt"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

/*
GenerateHeadersSchemePayloads generates payloads by adding headers related to protocol
schemes (e.g., HTTP, HTTPS) with values sourced from predefined lists.

It reads potential scheme-related header names from header_proto_schemes.lst and
a list of protocol schemes (http, https, etc.) from internal_proto_schemes.lst.

Key functionalities include:
1.  **Standard Payloads:** Combines most header names with each protocol scheme value.
2.  **Special HTTPS Headers:** Sets specific headers (`Front-End-Https`, `X-Forwarded-HTTPS`, `X-Forwarded-SSL`) to the value "on".
3.  **Special Handling for 'Forwarded' Header:** Formats the value as `proto={scheme}`.

The original URL's method, scheme, host, path, and query string are preserved in the
base structure of each generated payload.
*/
func (pg *PayloadGenerator) GenerateHeadersSchemePayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
		return allJobs
	}

	headerSchemes, err := ReadPayloadsFromFile("header_proto_schemes.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read header schemes: %v", err)
		return allJobs
	}

	protoSchemes, err := ReadPayloadsFromFile("internal_proto_schemes.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read proto schemes: %v", err)
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

	// Handle special headers with "on" value
	specialHeaders := map[string]struct{}{
		"Front-End-Https":   {},
		"X-Forwarded-HTTPS": {},
		"X-Forwarded-SSL":   {},
	}

	for _, headerScheme := range headerSchemes {
		if _, isSpecial := specialHeaders[headerScheme]; isSpecial {
			job := baseJob
			job.Headers = []Headers{{
				Header: headerScheme,
				Value:  "on",
			}}
			job.PayloadToken = GeneratePayloadToken(job)
			allJobs = append(allJobs, job)
			continue
		}

		// Handle other headers
		for _, protoScheme := range protoSchemes {
			job := baseJob
			if headerScheme == "Forwarded" {
				job.Headers = []Headers{{
					Header: headerScheme,
					Value:  fmt.Sprintf("proto=%s", protoScheme),
				}}
			} else {
				job.Headers = []Headers{{
					Header: headerScheme,
					Value:  protoScheme,
				}}
			}

			job.PayloadToken = GeneratePayloadToken(job)
			allJobs = append(allJobs, job)
		}
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(allJobs), targetURL)
	return allJobs
}
