// payloads.go
package main

import (
	"fmt"
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
)

type PayloadJob struct {
	method     string
	url        string
	headers    []Header
	bypassMode string
}

func generateMidPathsJobs(targetURL string) []PayloadJob {
	_bypassMode := "mid_paths"
	var jobs []PayloadJob
	parsedURL := rawurlparser.RawURLParse(targetURL)
	if parsedURL == nil {
		LogError("Failed to parse URL")
		return jobs // Return empty slice instead of nil
	}

	LogVerbose("Starting MidPaths payload generation for: %s", targetURL)

	payloads, err := readPayloadsFile("payloads/internal_midpaths.lst")
	if err != nil {
		LogError("Failed to read midpaths payloads: %v", err)
		return jobs // Return empty slice instead of nil
	}

	path := parsedURL.Path
	if path == "" {
		path = "/"
	}

	slashCount := strings.Count(path, "/")
	if slashCount == 0 {
		slashCount = 1
	}

	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// collect all URLs first
	urls := make(map[string]bool)

	for idxSlash := 0; idxSlash < slashCount; idxSlash++ {
		for _, payload := range payloads {
			// Post-slash variants (always)
			pathPost := ReplaceNth(path, "/", "/"+payload, idxSlash+1)
			if pathPost != path { // Only add if replacement was successful
				// First and second variants
				urls[fmt.Sprintf("%s%s", baseURL, pathPost)] = true
				urls[fmt.Sprintf("%s/%s", baseURL, pathPost)] = true
			}

			// Pre-slash variants only if idxSlash > 1
			if idxSlash > 1 {
				pathPre := ReplaceNth(path, "/", payload+"/", idxSlash+1)
				if pathPre != path { // Only add if replacement was successful
					// First and second variants
					urls[fmt.Sprintf("%s%s", baseURL, pathPre)] = true
					urls[fmt.Sprintf("%s/%s", baseURL, pathPre)] = true
				}
			}
		}
	}

	LogYellow("\n[%s] Generated %d payloads for %s\n", _bypassMode, len(urls), targetURL)

	// Convert URLs to PayloadJobs
	for url := range urls {
		jobs = append(jobs, PayloadJob{
			method:     "GET",
			url:        url,
			bypassMode: _bypassMode,
		})
	}

	return jobs
}

func generateEndPathsJobs(targetURL string) []PayloadJob {
	_bypassMode := "end_paths"
	var jobs []PayloadJob

	LogVerbose("Starting EndPaths payload generation for: %s", targetURL)

	parsedURL := rawurlparser.RawURLParse(targetURL)
	if parsedURL == nil {
		LogError("Failed to parse URL")
		return jobs
	}

	payloads, err := readPayloadsFile("payloads/internal_endpaths.lst")
	if err != nil {
		LogError("Failed to read endpaths payloads: %v", err)
		return jobs
	}

	basePath := parsedURL.Path
	separator := ""
	if basePath != "/" && !strings.HasSuffix(basePath, "/") {
		separator = "/"
	}

	baseURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, basePath)

	// collect all URLs first
	urls := make(map[string]bool)

	for _, payload := range payloads {
		// First variant - 'url/suffix'
		urls[baseURL+separator+payload] = true

		// Second variant - 'url/suffix/'
		urls[baseURL+separator+payload+"/"] = true

		// Only if basePath is not "/" and payload doesn't start with a letter
		if basePath != "/" {
			if !isLetter(payload[0]) {
				// Third variant - Add 'suffix'
				urls[baseURL+payload] = true

				// Fourth variant - Add 'suffix/'
				urls[baseURL+payload+"/"] = true
			}
		}
	}

	LogYellow("\n[%s] Generated %d payloads for %s\n", _bypassMode, len(urls), targetURL)

	// Convert URLs to jobs
	for url := range urls {
		jobs = append(jobs, PayloadJob{
			method:     "GET",
			url:        url,
			bypassMode: _bypassMode,
		})
	}

	return jobs
}

func generateHeaderIPJobs(targetURL string) []PayloadJob {
	_bypassMode := "http_headers_ip"
	var allJobs []PayloadJob

	LogVerbose("Starting HeadersIP payload generation for: %s", targetURL)

	headerNames, err := readPayloadsFile("payloads/header_ip_hosts.lst")
	if err != nil {
		LogError("Failed to read header names: %v", err)
		return allJobs
	}

	// Add custom headers (cli -spoof-header)
	if config.SpoofHeader != "" {
		customHeaders := strings.Split(config.SpoofHeader, ",")
		for _, header := range customHeaders {
			header = strings.TrimSpace(header)
			if header != "" {
				headerNames = append(headerNames, header)
			}
		}
		LogYellow("[%s] Added [%s] custom headers from -spoof-header\n", _bypassMode, strings.Join(customHeaders, ","))
	}

	ips, err := readPayloadsFile("payloads/internal_ip_hosts.lst")
	if err != nil {
		LogError("Failed to read IPs: %v", err)
		return allJobs
	}

	// Add custom spoof IPs
	if config.SpoofIP != "" {
		customIPs := strings.Split(config.SpoofIP, ",")
		for _, ip := range customIPs {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				ips = append(ips, ip)
			}
		}
		LogYellow("[%s] Added [%s] custom IPs from -spoof-ip\n", _bypassMode, strings.Join(customIPs, ","))
	}

	// Special case job
	allJobs = append(allJobs, PayloadJob{
		method: "GET",
		url:    targetURL,
		headers: []Header{{
			Key:   "X-AppEngine-Trusted-IP-Request",
			Value: "1",
		}},
		bypassMode: _bypassMode,
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
						method: "GET",
						url:    targetURL,
						headers: []Header{{
							Key:   headerName,
							Value: variation,
						}},
						bypassMode: _bypassMode,
					})
				}
			} else {
				allJobs = append(allJobs, PayloadJob{
					method: "GET",
					url:    targetURL,
					headers: []Header{{
						Key:   headerName,
						Value: ip,
					}},
					bypassMode: _bypassMode,
				})
			}
		}
	}

	LogYellow("\n[%s] Generated %d payloads for %s\n", _bypassMode, len(allJobs), targetURL)
	return allJobs
}

func generateCaseSubstitutionJobs(targetURL string) []PayloadJob {
	_bypassMode := "case_substitution"
	var allJobs []PayloadJob

	LogVerbose("Starting CaseSubstitution payload generation for: %s", targetURL)

	parsedURL := rawurlparser.RawURLParse(targetURL)
	if parsedURL == nil {
		LogError("Failed to parse URL")
		return allJobs
	}

	basePath := parsedURL.Path
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

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

			allJobs = append(allJobs, PayloadJob{
				method:     "GET",
				url:        baseURL + newPath,
				bypassMode: _bypassMode,
			})
		}
	}

	LogYellow("\n[%s] Generated %d payloads for %s\n", _bypassMode, len(allJobs), targetURL)
	return allJobs
}

func generateCharEncodeJobs(targetURL string) []PayloadJob {
	var allJobs []PayloadJob

	LogVerbose("Starting CharEncode payload generation for: %s", targetURL)

	parsedURL := rawurlparser.RawURLParse(targetURL)
	if parsedURL == nil {
		LogError("Failed to parse URL")
		return allJobs
	}

	basePath := parsedURL.Path
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// Find all letter positions
	for i, char := range basePath {
		if isLetter(byte(char)) {
			// Single URL encoding
			encoded := fmt.Sprintf("%%%02x", char)
			singleEncoded := basePath[:i] + encoded + basePath[i+1:]
			allJobs = append(allJobs, PayloadJob{
				method:     "GET",
				url:        baseURL + singleEncoded,
				bypassMode: "char_encode",
			})

			// Double URL encoding
			doubleEncoded := basePath[:i] + "%25" + encoded[1:] + basePath[i+1:]
			allJobs = append(allJobs, PayloadJob{
				method:     "GET",
				url:        baseURL + doubleEncoded,
				bypassMode: "char_encode_double",
			})

			// Triple URL encoding
			tripleEncoded := basePath[:i] + "%2525" + encoded[1:] + basePath[i+1:]
			allJobs = append(allJobs, PayloadJob{
				method:     "GET",
				url:        baseURL + tripleEncoded,
				bypassMode: "char_encode_triple",
			})
		}
	}

	LogYellow("\n[char_encode] Generated %d payloads for %s\n", len(allJobs), targetURL)
	return allJobs
}

func generateHeaderSchemeJobs(targetURL string) []PayloadJob {
	_bypassMode := "http_headers_scheme"
	var allJobs []PayloadJob

	LogVerbose("Starting HeadersScheme payload generation for: %s", targetURL)

	headerSchemes, err := readPayloadsFile("payloads/header_proto_schemes.lst")
	if err != nil {
		LogError("Failed to read header schemes: %v", err)
		return allJobs
	}

	protoSchemes, err := readPayloadsFile("payloads/internal_proto_schemes.lst")
	if err != nil {
		LogError("Failed to read proto schemes: %v", err)
		return allJobs
	}

	for _, headerScheme := range headerSchemes {
		if headerScheme == "Front-End-Https" ||
			headerScheme == "X-Forwarded-HTTPS" ||
			headerScheme == "X-Forwarded-SSL" {
			allJobs = append(allJobs, PayloadJob{
				method: "GET",
				url:    targetURL,
				headers: []Header{{
					Key:   headerScheme,
					Value: "on",
				}},
				bypassMode: _bypassMode,
			})
			continue
		}

		// Handle other headers
		for _, protoScheme := range protoSchemes {
			if headerScheme == "Forwarded" {
				allJobs = append(allJobs, PayloadJob{
					method: "GET",
					url:    targetURL,
					headers: []Header{{
						Key:   headerScheme,
						Value: fmt.Sprintf("proto=%s", protoScheme),
					}},
					bypassMode: _bypassMode,
				})
			} else {
				allJobs = append(allJobs, PayloadJob{
					method: "GET",
					url:    targetURL,
					headers: []Header{{
						Key:   headerScheme,
						Value: protoScheme,
					}},
					bypassMode: _bypassMode,
				})
			}
		}
	}

	LogYellow("\n[%s] Generated %d payloads for %s\n", _bypassMode, len(allJobs), targetURL)
	return allJobs
}

func generateHeaderURLJobs(targetURL string) []PayloadJob {
	_bypassMode := "http_headers_url"
	var allJobs []PayloadJob

	LogVerbose("Starting HeadersURL payload generation for: %s", targetURL)

	parsedURL := rawurlparser.RawURLParse(targetURL)
	if parsedURL == nil {
		LogError("Failed to parse URL")
		return allJobs
	}

	headerURLs, err := readPayloadsFile("payloads/header_urls.lst")
	if err != nil {
		LogError("Failed to read header URLs: %v", err)
		return allJobs
	}

	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	basePath := strings.TrimRight(parsedURL.Path, "/")
	if basePath == "" {
		basePath = "/"
	}

	for _, headerURL := range headerURLs {
		// First variant: base_path in header
		allJobs = append(allJobs, PayloadJob{
			method: "GET",
			url:    baseURL + "/",
			headers: []Header{{
				Key:   headerURL,
				Value: basePath,
			}},
			bypassMode: _bypassMode,
		})

		// Second variant: full target URL in header
		if strings.Contains(strings.ToLower(headerURL), "url") ||
			strings.Contains(strings.ToLower(headerURL), "request") ||
			strings.Contains(strings.ToLower(headerURL), "file") {
			allJobs = append(allJobs, PayloadJob{
				method: "GET",
				url:    baseURL + "/",
				headers: []Header{{
					Key:   headerURL,
					Value: targetURL,
				}},
				bypassMode: _bypassMode,
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
				method: "GET",
				url:    targetURL,
				headers: []Header{{
					Key:   headerURL,
					Value: parentPath,
				}},
				bypassMode: _bypassMode,
			})

			if strings.Contains(strings.ToLower(headerURL), "url") ||
				strings.Contains(strings.ToLower(headerURL), "refer") {
				fullURL := baseURL + parentPath
				allJobs = append(allJobs, PayloadJob{
					method: "GET",
					url:    targetURL,
					headers: []Header{{
						Key:   headerURL,
						Value: fullURL,
					}},
					bypassMode: _bypassMode,
				})
			}
		}
	}

	LogYellow("\n[%s] Generated %d payloads for %s\n", _bypassMode, len(allJobs), targetURL)
	return allJobs
}

func generateHeaderPortJobs(targetURL string) []PayloadJob {
	_bypassMode := "http_headers_port"
	var allJobs []PayloadJob

	LogVerbose("Starting HeadersPort payload generation for: %s", targetURL)

	headerPorts, err := readPayloadsFile("payloads/header_ports.lst")
	if err != nil {
		LogError("Failed to read header ports: %v", err)
		return allJobs
	}

	internalPorts, err := readPayloadsFile("payloads/internal_ports.lst")
	if err != nil {
		LogError("Failed to read internal ports: %v", err)
		return allJobs
	}

	for _, headerPort := range headerPorts {
		if headerPort == "" {
			continue
		}

		// Handle internal ports
		for _, port := range internalPorts {
			allJobs = append(allJobs, PayloadJob{
				method: "GET",
				url:    targetURL,
				headers: []Header{{
					Key:   headerPort,
					Value: port,
				}},
				bypassMode: _bypassMode,
			})
		}
	}

	LogYellow("\n[%s] Generated %d payloads for %s\n", _bypassMode, len(allJobs), targetURL)
	return allJobs
}
