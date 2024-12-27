package payload

import (
	"fmt"
	"strings"

	"github.com/slicingmelon/go-bypass-403/internal/engine/recon"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/slicingmelon/go-rawurlparser"
)

type PayloadGenerator struct {
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

func NewPayloadGenerator() *PayloadGenerator {
	return &PayloadGenerator{}
}

func (pg *PayloadGenerator) GenerateDumbJob(targetURL string, bypassModule string) []PayloadJob {
	var allJobs []PayloadJob

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
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

	GB403Logger.Info().BypassModule(bypassModule).Msgf("Generated 1 payload for %s", targetURL)
	return allJobs
}

func (pg *PayloadGenerator) GenerateMidPathsJobs(targetURL string, bypassModule string) []PayloadJob {
	var jobs []PayloadJob
	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
		return jobs
	}

	payloads, err := ReadPayloadsFromFile("internal_midpaths.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read midpaths payloads: %v", err)
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

	GB403Logger.Info().BypassModule(bypassModule).Msgf("Generated %d payloads for %s", len(urls), targetURL)

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

func (pg *PayloadGenerator) GenerateEndPathsJobs(targetURL string, bypassModule string) []PayloadJob {
	var jobs []PayloadJob

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
		return jobs
	}

	payloads, err := ReadPayloadsFromFile("internal_endpaths.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read endpaths payloads: %v", err)
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

	GB403Logger.Info().BypassModule(bypassModule).Msgf("Generated %d payloads for %s", len(urls), targetURL)

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

func (pg *PayloadGenerator) GenerateHeaderIPJobs(targetURL string, bypassModule string, spoofHeader string, spoofIP string) []PayloadJob {
	var allJobs []PayloadJob

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
	if spoofHeader != "" {
		customHeaders := strings.Split(spoofHeader, ",")
		for _, header := range customHeaders {
			header = strings.TrimSpace(header)
			if header != "" {
				headerNames = append(headerNames, header)
			}
		}
		GB403Logger.Info().BypassModule(bypassModule).Msgf("Added [%s] custom headers from -spoof-header\n", strings.Join(customHeaders, ","))
	}

	ips, err := ReadPayloadsFromFile("internal_ip_hosts.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read IPs: %v", err)
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
		GB403Logger.Info().BypassModule(bypassModule).Msgf("Added [%s] custom IPs from -spoof-ip\n", strings.Join(customIPs, ","))
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

	GB403Logger.Info().Msgf("[%s] Generated %d payloads for %s", bypassModule, len(allJobs), targetURL)
	return allJobs
}

func (pg *PayloadGenerator) GenerateCaseSubstitutionJobs(targetURL string, bypassModule string) []PayloadJob {
	var allJobs []PayloadJob

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
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

	GB403Logger.Info().BypassModule(bypassModule).Msgf("Generated %d payloads for %s", len(allJobs), targetURL)
	return allJobs
}

func (pg *PayloadGenerator) GenerateCharEncodeJobs(targetURL string, bypassModule string) []PayloadJob {
	var allJobs []PayloadJob

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
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
	GB403Logger.Info().BypassModule(bypassModule).Msgf("Generated %d payloads for %s", totalJobs, targetURL)
	return allJobs
}

func (pg *PayloadGenerator) GenerateHeaderSchemeJobs(targetURL string, bypassModule string) []PayloadJob {
	var allJobs []PayloadJob

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

	GB403Logger.Info().BypassModule(bypassModule).Msgf("Generated %d payloads for %s", len(allJobs), targetURL)
	return allJobs
}

func (pg *PayloadGenerator) GenerateHeaderURLJobs(targetURL string, bypassModule string) []PayloadJob {
	var allJobs []PayloadJob

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

	GB403Logger.Info().BypassModule(bypassModule).Msgf("Generated %d payloads for %s", len(allJobs), targetURL)
	return allJobs
}

func (pg *PayloadGenerator) GenerateHeaderPortJobs(targetURL string, bypassModule string) []PayloadJob {
	var allJobs []PayloadJob

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

	GB403Logger.Info().BypassModule(bypassModule).Msgf("Generated %d payloads for %s", len(allJobs), targetURL)
	return allJobs
}

func (pg *PayloadGenerator) GenerateHostHeaderJobs(targetURL string, bypassModule string, reconCache *recon.ReconCache) []PayloadJob {
	var allJobs []PayloadJob

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
		return allJobs
	}

	// Extract base URL components
	pathAndQuery := parsedURL.Path
	if parsedURL.Query != "" {
		pathAndQuery += "?" + parsedURL.Query
	}

	// Get IP information from cache
	probeCacheResult, err := reconCache.Get(parsedURL.Hostname())
	if err != nil || probeCacheResult == nil {
		GB403Logger.Error().Msgf("No cache result found for %s: %v", targetURL, err)
		return allJobs
	}

	// Process IPv4 Services
	for scheme, ips := range probeCacheResult.IPv4Services {
		for ip, ports := range ips {
			for _, port := range ports {
				// Create temporary URL object for base URL construction
				ipURL := &rawurlparser.RawURL{
					Scheme: scheme,
					Host:   ip,
				}
				if port != "80" && port != "443" {
					ipURL.Host = fmt.Sprintf("%s:%s", ip, port)
				}

				// Variation 1: URL with IP, Host header with original host
				fullURL := ipURL.BaseURL() + pathAndQuery
				allJobs = append(allJobs, PayloadJob{
					OriginalURL: targetURL,
					Method:      "GET",
					Host:        ipURL.Host,
					RawURI:      pathAndQuery,
					Headers: []Header{{
						Header: "Host",
						Value:  parsedURL.Host,
					}},
					FullURL:      fullURL,
					BypassModule: bypassModule,
					PayloadToken: GenerateDebugToken(SeedData{Headers: []Header{{Header: "Host", Value: parsedURL.Host}}, FullURL: fullURL}),
				})

				// Variation 2: Original URL, Host header with IP:port
				hostValue := ipURL.Host
				allJobs = append(allJobs, PayloadJob{
					OriginalURL: targetURL,
					Method:      "GET",
					Host:        parsedURL.Host,
					RawURI:      pathAndQuery,
					Headers: []Header{{
						Header: "Host",
						Value:  hostValue,
					}},
					FullURL:      targetURL,
					BypassModule: bypassModule,
					PayloadToken: GenerateDebugToken(SeedData{Headers: []Header{{Header: "Host", Value: hostValue}}, FullURL: targetURL}),
				})
			}
		}
	}

	// Process IPv6 Services
	for scheme, ips := range probeCacheResult.IPv6Services {
		for ip, ports := range ips {
			for _, port := range ports {
				// Create temporary URL object for base URL construction
				ipURL := &rawurlparser.RawURL{
					Scheme: scheme,
					Host:   fmt.Sprintf("[%s]", ip),
				}
				if port != "80" && port != "443" {
					ipURL.Host = fmt.Sprintf("[%s]:%s", ip, port)
				}

				// Variation 1: URL with IPv6, Host header with original host
				fullURL := ipURL.BaseURL() + pathAndQuery
				allJobs = append(allJobs, PayloadJob{
					OriginalURL: targetURL,
					Method:      "GET",
					Host:        ipURL.Host,
					RawURI:      pathAndQuery,
					Headers: []Header{{
						Header: "Host",
						Value:  parsedURL.Host,
					}},
					FullURL:      fullURL,
					BypassModule: bypassModule,
					PayloadToken: GenerateDebugToken(SeedData{Headers: []Header{{Header: "Host", Value: parsedURL.Host}}, FullURL: fullURL}),
				})

				// Variation 2: Original URL, Host header with IPv6
				hostValue := ipURL.Host
				allJobs = append(allJobs, PayloadJob{
					OriginalURL: targetURL,
					Method:      "GET",
					Host:        parsedURL.Host,
					RawURI:      pathAndQuery,
					Headers: []Header{{
						Header: "Host",
						Value:  hostValue,
					}},
					FullURL:      targetURL,
					BypassModule: bypassModule,
					PayloadToken: GenerateDebugToken(SeedData{Headers: []Header{{Header: "Host", Value: hostValue}}, FullURL: targetURL}),
				})
			}
		}
	}

	GB403Logger.Info().BypassModule(bypassModule).Msgf("Generated %d payloads for %s", len(allJobs), targetURL)
	return allJobs
}
