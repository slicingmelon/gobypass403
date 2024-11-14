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

func generateMidPathsJobs(targetURL string, jobs chan<- PayloadJob) {
	parsedURL := rawurlparser.RawURLParse(targetURL)
	if parsedURL == nil {
		LogError("Failed to parse URL")
		return
	}

	LogDebug("Starting MidPaths payload generation for: %s", targetURL)

	payloads, err := readPayloadsFile("payloads/internal_midpaths.lst")
	if err != nil {
		LogError("Failed to read midpaths payloads: %v", err)
		return
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

	LogYellow("[mid_paths] Generated %d payloads for %s", len(urls), targetURL)
	for url := range urls {
		jobs <- PayloadJob{
			method:     "GET",
			url:        url,
			bypassMode: ModeMidPaths,
		}
	}
}

func generateEndPathsJobs(targetURL string, jobs chan<- PayloadJob) {
	LogDebug("Starting EndPaths payload generation for: %s", targetURL)

	parsedURL := rawurlparser.RawURLParse(targetURL)
	if parsedURL == nil {
		LogError("Failed to parse URL")
		return
	}

	payloads, err := readPayloadsFile("payloads/internal_endpaths.lst")
	if err != nil {
		LogError("Failed to read endpaths payloads: %v", err)
		return
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

	LogYellow("[end_paths] Generated %d payloads for %s", len(urls), targetURL)
	for url := range urls {
		jobs <- PayloadJob{
			method:     "GET",
			url:        url,
			bypassMode: ModeEndPaths,
		}
	}
}

func generateHeaderIPJobs(targetURL string, jobs chan<- PayloadJob) {
	LogDebug("Starting HeadersIP payload generation for: %s", targetURL)

	headerNames, err := readPayloadsFile("payloads/header_ip_hosts.lst")
	if err != nil {
		LogError("Failed to read header names: %v", err)
		return
	}

	ips, err := readPayloadsFile("payloads/internal_ip_hosts.lst")
	if err != nil {
		LogError("Failed to read IPs: %v", err)
		return
	}

	allJobs := make([]PayloadJob, 0)

	// Special case job
	allJobs = append(allJobs, PayloadJob{
		method: "GET",
		url:    targetURL,
		headers: []Header{{
			Key:   "X-AppEngine-Trusted-IP-Request",
			Value: "1",
		}},
		bypassMode: ModeHeadersIP,
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
						bypassMode: ModeHeadersIP,
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
					bypassMode: ModeHeadersIP,
				})
			}
		}
	}

	LogYellow("[headers_ip] Generated %d payloads for %s", len(allJobs), targetURL)
	for _, job := range allJobs {
		jobs <- job
	}
}

func generateCaseSubstitutionJobs(targetURL string, jobs chan<- PayloadJob) {
	LogDebug("Starting CaseSubstitution payload generation for: %s", targetURL)

	parsedURL := rawurlparser.RawURLParse(targetURL)
	if parsedURL == nil {
		LogError("Failed to parse URL")
		return
	}

	basePath := parsedURL.Path
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// collect all jobs first
	allJobs := make([]PayloadJob, 0)

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
				bypassMode: ModeCaseSubstitution,
			})
		}
	}

	LogYellow("[case_substitution] Generated %d payloads for %s", len(allJobs), targetURL)
	for _, job := range allJobs {
		jobs <- job
	}
}

func generateCharEncodeJobs(targetURL string, jobs chan<- PayloadJob) {
	LogDebug("Starting CharEncode payload generation for: %s", targetURL)

	parsedURL := rawurlparser.RawURLParse(targetURL)
	if parsedURL == nil {
		LogError("Failed to parse URL")
		return
	}

	basePath := parsedURL.Path
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	allJobs := make([]PayloadJob, 0)

	// Find all letter positions
	for i, char := range basePath {
		if isLetter(byte(char)) {
			// Single URL encoding
			encoded := fmt.Sprintf("%%%02x", char)
			singleEncoded := basePath[:i] + encoded + basePath[i+1:]
			allJobs = append(allJobs, PayloadJob{
				method:     "GET",
				url:        baseURL + singleEncoded,
				bypassMode: ModeCharEncode,
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

	LogYellow("[char_encode] Generated %d payloads for %s", len(allJobs), targetURL)
	for _, job := range allJobs {
		jobs <- job
	}
}

func generateHeaderSchemeJobs(targetURL string, jobs chan<- PayloadJob) {
	LogDebug("Starting HeadersScheme payload generation for: %s", targetURL)

	headerSchemes, err := readPayloadsFile("payloads/header_proto_schemes.lst")
	if err != nil {
		LogError("Failed to read header schemes: %v", err)
		return
	}

	protoSchemes, err := readPayloadsFile("payloads/internal_proto_schemes.lst")
	if err != nil {
		LogError("Failed to read proto schemes: %v", err)
		return
	}

	// collect all jobs
	allJobs := make([]PayloadJob, 0)

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
				bypassMode: ModeHeadersScheme,
			})
			continue
		}

		// Handle other headers
		for _, protoScheme := range protoSchemes {
			if headerScheme == "Forwarded" {
				// Specific rule for Forwarded header
				allJobs = append(allJobs, PayloadJob{
					method: "GET",
					url:    targetURL,
					headers: []Header{{
						Key:   headerScheme,
						Value: fmt.Sprintf("proto=%s", protoScheme),
					}},
					bypassMode: ModeHeadersScheme,
				})
			} else {
				// Standard headers
				allJobs = append(allJobs, PayloadJob{
					method: "GET",
					url:    targetURL,
					headers: []Header{{
						Key:   headerScheme,
						Value: protoScheme,
					}},
					bypassMode: ModeHeadersScheme,
				})
			}
		}
	}

	LogYellow("[headers_scheme] Generated %d payloads for %s", len(allJobs), targetURL)
	for _, job := range allJobs {
		jobs <- job
	}
}

func generateHeaderURLJobs(targetURL string, jobs chan<- PayloadJob) {
	LogDebug("Starting HeadersURL payload generation for: %s", targetURL)

	parsedURL := rawurlparser.RawURLParse(targetURL)
	if parsedURL == nil {
		LogError("Failed to parse URL")
		return
	}

	headerURLs, err := readPayloadsFile("payloads/header_urls.lst")
	if err != nil {
		LogError("Failed to read header URLs: %v", err)
		return
	}

	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	basePath := strings.TrimRight(parsedURL.Path, "/")
	if basePath == "" {
		basePath = "/"
	}

	// collect all jobs
	allJobs := make([]PayloadJob, 0)

	for _, headerURL := range headerURLs {
		// First variant: base_path in header
		allJobs = append(allJobs, PayloadJob{
			method: "GET",
			url:    baseURL + "/",
			headers: []Header{{
				Key:   headerURL,
				Value: basePath,
			}},
			bypassMode: ModeHeadersURL,
		})

		// Second variant: full target URL in header (for specific headers)
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
				bypassMode: ModeHeadersURL,
			})
		}

		// Third and Fourth variants: parent paths
		parts := strings.Split(strings.Trim(basePath, "/"), "/")
		for i := len(parts) - 1; i >= 0; i-- {
			parentPath := "/" + strings.Join(parts[:i], "/")
			if parentPath == "/" {
				parentPath = "/"
			}

			// Third variant: parent path only
			allJobs = append(allJobs, PayloadJob{
				method: "GET",
				url:    targetURL,
				headers: []Header{{
					Key:   headerURL,
					Value: parentPath,
				}},
				bypassMode: ModeHeadersURL,
			})

			// Fourth variant: full URL with parent path
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
					bypassMode: ModeHeadersURL,
				})
			}
		}
	}

	LogYellow("[headers_url] Generated %d payloads for %s", len(allJobs), targetURL)
	for _, job := range allJobs {
		jobs <- job
	}
}

func generateHeaderPortJobs(targetURL string, jobs chan<- PayloadJob) {
	LogDebug("Starting HeadersPort payload generation for: %s", targetURL)

	headerPorts, err := readPayloadsFile("payloads/header_ports.lst")
	if err != nil {
		LogError("Failed to read header ports: %v", err)
		return
	}

	internalPorts, err := readPayloadsFile("payloads/internal_ports.lst")
	if err != nil {
		LogError("Failed to read internal ports: %v", err)
		return
	}

	allJobs := make([]PayloadJob, 0)

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
				bypassMode: ModeHeadersPort,
			})
		}
	}

	LogYellow("[headers_port] Generated %d payloads for %s", len(allJobs), targetURL)
	for _, job := range allJobs {
		jobs <- job
	}
}
