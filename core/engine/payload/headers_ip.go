package payload

import (
	"fmt"
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

/*
GenerateHeaderIPPayloads generates payloads by adding various IP/Host related headers.

It reads base header names from header_ip_hosts.lst and IP values from internal_ip_hosts.lst.
It incorporates custom headers provided via the '-spoof-header' CLI flag, adding both the
original casing and the canonicalized (normalized) version for each custom header.
It also incorporates custom IPs provided via the '-spoof-ip' CLI flag.
*/
func (pg *PayloadGenerator) GenerateHeadersIPPayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL: %s", targetURL)
		return allJobs
	}

	// Load standard header names
	headerNamesSet := make(map[string]struct{}) // Use a set to avoid duplicates from list/CLI
	standardHeaderNames, err := ReadPayloadsFromFile("header_ip_hosts.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read header names: %v", err)
		// Continue even if standard list fails, custom headers might still be provided
	} else {
		for _, h := range standardHeaderNames {
			headerNamesSet[h] = struct{}{}
		}
	}

	// Add custom headers (cli -spoof-header) - Both original and normalized
	if pg.spoofHeader != "" {
		customHeaders := strings.Split(pg.spoofHeader, ",")
		var addedCustomHeaders []string // For logging clarity
		for _, header := range customHeaders {
			originalHeader := strings.TrimSpace(header)
			if originalHeader == "" {
				continue
			}

			// Add the original header (as provided, just trimmed)
			if _, exists := headerNamesSet[originalHeader]; !exists {
				headerNamesSet[originalHeader] = struct{}{}
				addedCustomHeaders = append(addedCustomHeaders, fmt.Sprintf("'%s'", originalHeader))
			}

			// Add the normalized version
			normalizedHeader := NormalizeHeaderKey(originalHeader)
			if normalizedHeader != originalHeader { // Only add normalized if different from original
				if _, exists := headerNamesSet[normalizedHeader]; !exists {
					headerNamesSet[normalizedHeader] = struct{}{}
					addedCustomHeaders = append(addedCustomHeaders, fmt.Sprintf("'%s' (normalized)", normalizedHeader))
				}
			}
		}
		if len(addedCustomHeaders) > 0 {
			GB403Logger.Verbose().BypassModule(bypassModule).Msgf("Added %d custom header variants from -spoof-header: %s\n", len(addedCustomHeaders), strings.Join(addedCustomHeaders, ", "))
		}
	}

	// Convert set back to slice
	headerNames := make([]string, 0, len(headerNamesSet))
	for h := range headerNamesSet {
		headerNames = append(headerNames, h)
	}

	ips, err := ReadPayloadsFromFile("internal_ip_hosts.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read IPs: %v", err)
		// Allow continuing if custom IPs are provided
	}

	// Add custom spoof IPs
	if pg.spoofIP != "" {
		customIPs := strings.Split(pg.spoofIP, ",")
		addedCount := 0
		for _, ip := range customIPs {
			trimmedIP := strings.TrimSpace(ip)
			if trimmedIP != "" {
				ips = append(ips, trimmedIP) // Simple append, duplicates handled by logic below if needed
				addedCount++
			}
		}
		if addedCount > 0 {
			GB403Logger.Verbose().BypassModule(bypassModule).Msgf("Added %d custom IPs from -spoof-ip: %s\n", addedCount, pg.spoofIP)
		}
	}

	// Deduplicate IPs just in case
	ipSet := make(map[string]struct{})
	uniqueIPs := make([]string, 0, len(ips))
	for _, ip := range ips {
		if _, exists := ipSet[ip]; !exists {
			ipSet[ip] = struct{}{}
			uniqueIPs = append(uniqueIPs, ip)
		}
	}

	// Extract path and query - Correctly handled
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

	// Special case job: X-AppEngine-Trusted-IP-Request
	specialJob := baseJob
	specialJob.Headers = []Headers{{
		Header: "X-AppEngine-Trusted-IP-Request",
		Value:  "1",
	}}
	specialJob.PayloadToken = GeneratePayloadToken(specialJob)
	allJobs = append(allJobs, specialJob)

	// Generate regular jobs
	for _, headerName := range headerNames {
		for _, ip := range uniqueIPs {
			// Special handling for "Forwarded" header according to RFC 7239
			if headerName == "Forwarded" {
				variations := []string{
					fmt.Sprintf("by=%s", ip),  // Interface receiving the request
					fmt.Sprintf("for=%s", ip), // Client initiating the request
					// "host" refers to original Host header, not IP, usually. Removed this variation.
					// "proto" handled by headers_scheme module
				}
				// Add combination if needed? e.g., for=ip;by=ip - Maybe too complex for now.

				for _, variation := range variations {
					job := baseJob
					job.Headers = []Headers{{
						Header: headerName, // Use the potentially unnormalized header name here
						Value:  variation,
					}}
					job.PayloadToken = GeneratePayloadToken(job)
					allJobs = append(allJobs, job)
				}
			} else { // Standard Header: IP format
				job := baseJob
				job.Headers = []Headers{{
					Header: headerName, // Use the potentially unnormalized header name here
					Value:  ip,
				}}
				job.PayloadToken = GeneratePayloadToken(job)
				allJobs = append(allJobs, job)
			}
		}
	}

	// Update log message format to be consistent
	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s", len(allJobs), targetURL)
	return allJobs
}
