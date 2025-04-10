package payload

import (
	"fmt"
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

/*
GenerateHeadersHostPayloads
*/
func (pg *PayloadGenerator) GenerateHeadersHostPayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
		return allJobs
	}

	// Extract path and query
	pathAndQuery := parsedURL.Path
	if parsedURL.Query != "" {
		pathAndQuery += "?" + parsedURL.Query
	}

	// Get IP information from cache
	probeCacheResult, err := pg.reconCache.Get(parsedURL.Hostname)
	if err != nil || probeCacheResult == nil {
		GB403Logger.Error().Msgf("No cache result found for %s: %v", targetURL, err)
		return allJobs
	}

	// Base job template
	baseJob := BypassPayload{
		OriginalURL:  targetURL,
		Method:       "GET",
		BypassModule: bypassModule,
	}

	// Process IPv4 Services
	for scheme, ips := range probeCacheResult.IPv4Services {
		for ip, ports := range ips {
			for _, port := range ports {
				// Construct IP host
				ipHost := ip
				if port != "80" && port != "443" {
					ipHost = fmt.Sprintf("%s:%s", ip, port)
				}

				// Variation 1: URL with IP, Host header with original host
				job1 := baseJob
				job1.Scheme = scheme
				job1.Host = ipHost
				job1.RawURI = pathAndQuery
				job1.Headers = []Headers{{
					Header: "Host",
					Value:  parsedURL.Host,
				}}
				job1.PayloadToken = GeneratePayloadToken(job1)
				allJobs = append(allJobs, job1)

				// Variation 2: Original URL, Host header with IP:port
				job2 := baseJob
				job2.Scheme = parsedURL.Scheme
				job2.Host = parsedURL.Host
				job2.RawURI = pathAndQuery
				job2.Headers = []Headers{{
					Header: "Host",
					Value:  ipHost,
				}}
				job2.PayloadToken = GeneratePayloadToken(job2)
				allJobs = append(allJobs, job2)
			}
		}
	}

	// Process IPv6 Services
	for scheme, ips := range probeCacheResult.IPv6Services {
		for ip, ports := range ips {
			for _, port := range ports {
				// Construct IPv6 host
				ipHost := fmt.Sprintf("[%s]", ip)
				if port != "80" && port != "443" {
					ipHost = fmt.Sprintf("[%s]:%s", ip, port)
				}

				// Variation 1: URL with IPv6, Host header with original host
				job1 := baseJob
				job1.Scheme = scheme
				job1.Host = ipHost
				job1.RawURI = pathAndQuery
				job1.Headers = []Headers{{
					Header: "Host",
					Value:  parsedURL.Host,
				}}
				job1.PayloadToken = GeneratePayloadToken(job1)
				allJobs = append(allJobs, job1)

				// Variation 2: Original URL, Host header with IPv6
				job2 := baseJob
				job2.Scheme = parsedURL.Scheme
				job2.Host = parsedURL.Host
				job2.RawURI = pathAndQuery
				job2.Headers = []Headers{{
					Header: "Host",
					Value:  ipHost,
				}}
				job2.PayloadToken = GeneratePayloadToken(job2)
				allJobs = append(allJobs, job2)
			}
		}
	}

	// Process CNAMEs - New section
	if len(probeCacheResult.CNAMEs) > 0 {
		//GB403Logger.Verbose().BypassModule(bypassModule).Msgf("Found %d CNAMEs for %s", len(probeCacheResult.CNAMEs), parsedURL.Hostname)

		for _, rawCname := range probeCacheResult.CNAMEs {
			// Strip trailing dot that's common in DNS responses
			cname := strings.TrimSuffix(rawCname, ".")

			// Skip if CNAME is empty after trimming
			if cname == "" {
				continue
			}

			// 1. Original URL + CNAME in Host header
			job1 := baseJob
			job1.Scheme = parsedURL.Scheme
			job1.Host = parsedURL.Host
			job1.RawURI = pathAndQuery
			job1.Headers = []Headers{{
				Header: "Host",
				Value:  cname,
			}}
			job1.PayloadToken = GeneratePayloadToken(job1)
			allJobs = append(allJobs, job1)

			// 2. URL with CNAME + original host in Host header
			job2 := baseJob
			job2.Scheme = parsedURL.Scheme
			job2.Host = cname
			job2.RawURI = pathAndQuery
			job2.Headers = []Headers{{
				Header: "Host",
				Value:  parsedURL.Host,
			}}
			job2.PayloadToken = GeneratePayloadToken(job2)
			allJobs = append(allJobs, job2)

			// 3. URL with CNAME + CNAME in Host header too
			job3 := baseJob
			job3.Scheme = parsedURL.Scheme
			job3.Host = cname
			job3.RawURI = pathAndQuery
			job3.Headers = []Headers{{
				Header: "Host",
				Value:  cname,
			}}
			job3.PayloadToken = GeneratePayloadToken(job3)
			allJobs = append(allJobs, job3)

			// 4. Partial CNAME suffix tests - recursive domain parts
			domainParts := strings.Split(cname, ".")
			if len(domainParts) > 2 { // Only if we have subdomains
				for i := 1; i < len(domainParts)-1; i++ {
					// Build partial domain from current position to the end
					partialDomain := strings.Join(domainParts[i:], ".")

					job := baseJob
					job.Scheme = parsedURL.Scheme
					job.Host = parsedURL.Host
					job.RawURI = pathAndQuery
					job.Headers = []Headers{{
						Header: "Host",
						Value:  partialDomain,
					}}
					job.PayloadToken = GeneratePayloadToken(job)
					allJobs = append(allJobs, job)
				}
			}
		}
	}

	GB403Logger.Verbose().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(allJobs), targetURL)
	return allJobs
}
