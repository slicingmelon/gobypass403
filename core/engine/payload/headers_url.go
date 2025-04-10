package payload

import (
	"fmt"
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

/*
GenerateHeaderURLPayloads
*/
func (pg *PayloadGenerator) GenerateHeaderURLPayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
		return allJobs
	}

	headerURLs, err := ReadPayloadsFromFile("header_urls.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read header URLs: %v", err)
		return allJobs
	}

	basePath := strings.TrimRight(parsedURL.Path, "/")
	if basePath == "" {
		basePath = "/"
	}

	// Extract query string if it exists
	query := ""
	if parsedURL.Query != "" {
		query = "?" + parsedURL.Query
	}

	// Create full path with query for RawURI
	fullPathWithQuery := parsedURL.Path
	if query != "" {
		fullPathWithQuery += query
	}

	// Base job template
	baseJob := BypassPayload{
		OriginalURL:  targetURL,
		Method:       "GET",
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		BypassModule: bypassModule,
	}

	for _, headerURL := range headerURLs {
		// First variant: base_path in header (don't add query to header)
		job := baseJob
		job.RawURI = "/"
		job.Headers = []Headers{{
			Header: headerURL,
			Value:  basePath,
		}}
		job.PayloadToken = GeneratePayloadToken(job)
		allJobs = append(allJobs, job)

		// Optional: Add variant with query in header value
		if query != "" {
			job := baseJob
			job.RawURI = "/"
			job.Headers = []Headers{{
				Header: headerURL,
				Value:  basePath + query,
			}}
			job.PayloadToken = GeneratePayloadToken(job)
			allJobs = append(allJobs, job)
		}

		// Second variant: full target URL in header (targetURL already includes query)
		if strings.Contains(strings.ToLower(headerURL), "url") ||
			strings.Contains(strings.ToLower(headerURL), "request") ||
			strings.Contains(strings.ToLower(headerURL), "file") {
			job := baseJob
			job.RawURI = "/"
			job.Headers = []Headers{{
				Header: headerURL,
				Value:  targetURL,
			}}
			job.PayloadToken = GeneratePayloadToken(job)
			allJobs = append(allJobs, job)
		}

		// Parent paths variants
		parts := strings.Split(strings.Trim(basePath, "/"), "/")
		for i := len(parts) - 1; i >= 0; i-- {
			parentPath := "/" + strings.Join(parts[:i], "/")
			if parentPath == "/" {
				parentPath = "/"
			}

			// Parent path in header, without query in header but with query in RawURI
			job := baseJob
			job.RawURI = fullPathWithQuery
			job.Headers = []Headers{{
				Header: headerURL,
				Value:  parentPath,
			}}
			job.PayloadToken = GeneratePayloadToken(job)
			allJobs = append(allJobs, job)

			// Optional: Parent path + query in header
			if query != "" {
				job := baseJob
				job.RawURI = fullPathWithQuery
				job.Headers = []Headers{{
					Header: headerURL,
					Value:  parentPath + query,
				}}
				job.PayloadToken = GeneratePayloadToken(job)
				allJobs = append(allJobs, job)
			}

			// Full URL with parent path in header
			if strings.Contains(strings.ToLower(headerURL), "url") ||
				strings.Contains(strings.ToLower(headerURL), "refer") {
				// Without query in header
				fullURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, parentPath)
				job := baseJob
				job.RawURI = fullPathWithQuery
				job.Headers = []Headers{{
					Header: headerURL,
					Value:  fullURL,
				}}
				job.PayloadToken = GeneratePayloadToken(job)
				allJobs = append(allJobs, job)

				// With query in header
				if query != "" {
					fullURLWithQuery := fmt.Sprintf("%s://%s%s%s", parsedURL.Scheme, parsedURL.Host, parentPath, query)
					job := baseJob
					job.RawURI = fullPathWithQuery
					job.Headers = []Headers{{
						Header: headerURL,
						Value:  fullURLWithQuery,
					}}
					job.PayloadToken = GeneratePayloadToken(job)
					allJobs = append(allJobs, job)
				}
			}
		}
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(allJobs), targetURL)
	return allJobs
}
