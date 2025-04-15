package payload

import (
	"fmt"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

/*
GenerateHTTPMethodsPayloads
*/
func (pg *PayloadGenerator) GenerateHTTPMethodsPayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
		return allJobs
	}

	httpMethods, err := ReadPayloadsFromFile("internal_http_methods.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read HTTP methods: %v", err)
		return allJobs
	}

	// Extract path and query
	path := parsedURL.Path
	query := ""
	if parsedURL.Query != "" {
		query = "?" + parsedURL.Query
	}

	// Base job template
	baseJob := BypassPayload{
		OriginalURL:  targetURL,
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		BypassModule: bypassModule,
	}

	// Methods that require Content-Length header
	requiresContentLength := map[string]struct{}{
		"POST":      {},
		"PUT":       {},
		"PATCH":     {},
		"PROPFIND":  {},
		"PROPPATCH": {},
		"MKCOL":     {},
		"LOCK":      {},
		"UNLOCK":    {},
		"DELETE":    {},
	}

	for _, method := range httpMethods {
		// Skip empty methods
		if method == "" {
			continue
		}

		// Basic case: method with original path+query
		job := baseJob
		job.Method = method
		job.RawURI = path + query

		// Add Content-Length header if needed
		if _, needsContentLength := requiresContentLength[method]; needsContentLength {
			job.Headers = append(job.Headers, Headers{
				Header: "Content-Length",
				Value:  "0",
			})

			// For POST requests, create an additional variant with query in body
			if method == "POST" && parsedURL.Query != "" {
				// Create a job with path only (no query) for POST
				postJob := baseJob
				postJob.Method = method
				postJob.RawURI = path // No query in URL

				// Set query as body data without the leading "?"
				bodyData := parsedURL.Query

				// Add proper headers for form data
				postJob.Headers = append(postJob.Headers, Headers{
					Header: "Content-Type",
					Value:  "application/x-www-form-urlencoded",
				})
				postJob.Headers = append(postJob.Headers, Headers{
					Header: "Content-Length",
					Value:  fmt.Sprintf("%d", len(bodyData)),
				})

				// Add the body data
				postJob.Body = bodyData

				postJob.PayloadToken = GeneratePayloadToken(postJob)
				allJobs = append(allJobs, postJob)
			}
		}

		// Generate token and add job (fixed from postJob to job)
		job.PayloadToken = GeneratePayloadToken(job)
		allJobs = append(allJobs, job)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(allJobs), targetURL)
	return allJobs
}
