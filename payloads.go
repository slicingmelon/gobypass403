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
	LogDebug("Starting MidPaths payload generation for: %s", targetURL)

	parsedURL := rawurlparser.RawURLParse(targetURL)
	if parsedURL == nil || parsedURL.Path == "" {
		LogError("Failed to parse URL or empty path")
		return
	}

	payloads, err := readPayloadsFile("payloads/internal_midpaths.lst")
	if err != nil {
		LogError("Failed to read midpaths payloads: %v", err)
		return
	}

	path := strings.Trim(parsedURL.Path, "/")
	slashCount := strings.Count(path, "/")
	LogDebug("Path: %s, slash count: %d", path, slashCount)
	LogDebug("Number of payloads from file: %d", len(payloads))

	// deduplicate URLs
	seen := make(map[string]bool)

	for idxSlash := 0; idxSlash <= slashCount; idxSlash++ {
		parts := strings.Split(path, "/")

		for _, payload := range payloads {
			// Post-slash variants (always)
			parts[idxSlash] = payload
			pathPost := strings.Join(parts, "/")

			urls := []string{
				fmt.Sprintf("%s://%s/%s", parsedURL.Scheme, parsedURL.Host, pathPost),
				fmt.Sprintf("%s://%s//%s", parsedURL.Scheme, parsedURL.Host, pathPost),
			}

			for _, url := range urls {
				if !seen[url] {
					seen[url] = true
					jobs <- PayloadJob{
						method:     "GET",
						url:        url,
						bypassMode: ModeMidPaths,
					}
				}
			}

			// Pre-slash variants only if idxSlash > 1
			if idxSlash > 1 {
				parts[idxSlash] = payload + "/"
				pathPre := strings.Join(parts, "/")

				urls = []string{
					fmt.Sprintf("%s://%s/%s", parsedURL.Scheme, parsedURL.Host, pathPre),
					fmt.Sprintf("%s://%s//%s", parsedURL.Scheme, parsedURL.Host, pathPre),
				}

				for _, url := range urls {
					if !seen[url] {
						seen[url] = true
						jobs <- PayloadJob{
							method:     "GET",
							url:        url,
							bypassMode: ModeMidPaths,
						}
					}
				}
			}
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

	// Special case job
	jobs <- PayloadJob{
		method: "GET",
		url:    targetURL,
		headers: []Header{{
			Key:   "X-AppEngine-Trusted-IP-Request",
			Value: "1",
		}},
		bypassMode: ModeHeadersIP,
	}

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
					jobs <- PayloadJob{
						method: "GET",
						url:    targetURL,
						headers: []Header{{
							Key:   headerName,
							Value: variation,
						}},
						bypassMode: ModeHeadersIP,
					}
				}
			} else {
				jobs <- PayloadJob{
					method: "GET",
					url:    targetURL,
					headers: []Header{{
						Key:   headerName,
						Value: ip,
					}},
					bypassMode: ModeHeadersIP,
				}
			}
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

	basePath := strings.Trim(parsedURL.Path, "/")
	separator := "/"
	if basePath == "" || strings.HasSuffix(parsedURL.Path, "/") {
		separator = ""
	}

	seen := make(map[string]bool)
	for _, payload := range payloads {
		// First variant - 'url/suffix'
		url1 := fmt.Sprintf("%s://%s/%s%s%s", parsedURL.Scheme, parsedURL.Host, basePath, separator, payload)
		// Second variant - 'url/suffix/'
		url2 := fmt.Sprintf("%s://%s/%s%s%s/", parsedURL.Scheme, parsedURL.Host, basePath, separator, payload)

		urls := []string{url1, url2}

		// Only if basePath is not "/" and payload doesn't start with a letter
		if basePath != "" && !isLetter(payload[0]) {
			// Third variant - Add 'suffix'
			url3 := fmt.Sprintf("%s://%s/%s%s", parsedURL.Scheme, parsedURL.Host, basePath, payload)
			// Fourth variant - Add 'suffix/'
			url4 := fmt.Sprintf("%s://%s/%s%s/", parsedURL.Scheme, parsedURL.Host, basePath, payload)
			urls = append(urls, url3, url4)
		}

		for _, url := range urls {
			if !seen[url] {
				seen[url] = true
				jobs <- PayloadJob{
					method:     "GET",
					url:        url,
					bypassMode: ModeEndPaths,
				}
			}
		}
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

			jobs <- PayloadJob{
				method:     "GET",
				url:        baseURL + newPath,
				bypassMode: ModeCaseSubstitution,
			}
		}
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

	// Find all letter positions
	for i, char := range basePath {
		if isLetter(byte(char)) {
			// Single URL encoding
			encoded := fmt.Sprintf("%%%02x", char)
			singleEncoded := basePath[:i] + encoded + basePath[i+1:]
			jobs <- PayloadJob{
				method:     "GET",
				url:        baseURL + singleEncoded,
				bypassMode: ModeCharEncode,
			}

			// Double URL encoding
			doubleEncoded := basePath[:i] + "%25" + encoded[1:] + basePath[i+1:]
			jobs <- PayloadJob{
				method:     "GET",
				url:        baseURL + doubleEncoded,
				bypassMode: "char_encode_double",
			}

			// Triple URL encoding
			tripleEncoded := basePath[:i] + "%2525" + encoded[1:] + basePath[i+1:]
			jobs <- PayloadJob{
				method:     "GET",
				url:        baseURL + tripleEncoded,
				bypassMode: "char_encode_triple",
			}
		}
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

	seen := make(map[string]bool)

	for _, headerScheme := range headerSchemes {
		// Special case for headers that take 'on' value
		if headerScheme == "Front-End-Https" ||
			headerScheme == "X-Forwarded-HTTPS" ||
			headerScheme == "X-Forwarded-SSL" {
			if !seen[headerScheme] {
				seen[headerScheme] = true
				jobs <- PayloadJob{
					method: "GET",
					url:    targetURL,
					headers: []Header{{
						Key:   headerScheme,
						Value: "on",
					}},
					bypassMode: ModeHeadersScheme,
				}
			}
			continue
		}

		// Handle other headers
		for _, protoScheme := range protoSchemes {
			headerValue := protoScheme
			if headerScheme == "Forwarded" {
				headerValue = fmt.Sprintf("proto=%s", protoScheme)
			}

			jobs <- PayloadJob{
				method: "GET",
				url:    targetURL,
				headers: []Header{{
					Key:   headerScheme,
					Value: headerValue,
				}},
				bypassMode: ModeHeadersScheme,
			}
		}
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

	seen := make(map[string]bool)

	for _, headerURL := range headerURLs {
		// First variant: base_path in header
		jobs <- PayloadJob{
			method: "GET",
			url:    baseURL + "/",
			headers: []Header{{
				Key:   headerURL,
				Value: basePath,
			}},
			bypassMode: ModeHeadersURL,
		}

		// Second variant: full target URL in header (for specific headers)
		if strings.Contains(strings.ToLower(headerURL), "url") ||
			strings.Contains(strings.ToLower(headerURL), "request") ||
			strings.Contains(strings.ToLower(headerURL), "file") {
			jobs <- PayloadJob{
				method: "GET",
				url:    baseURL + "/",
				headers: []Header{{
					Key:   headerURL,
					Value: targetURL,
				}},
				bypassMode: ModeHeadersURL,
			}
		}

		// Third and Fourth variants: parent paths
		parts := strings.Split(strings.Trim(basePath, "/"), "/")
		for i := len(parts) - 1; i >= 0; i-- {
			parentPath := "/" + strings.Join(parts[:i], "/")
			if parentPath == "/" {
				parentPath = "/"
			}

			// Third variant: parent path only
			if !seen[headerURL+parentPath] {
				seen[headerURL+parentPath] = true
				jobs <- PayloadJob{
					method: "GET",
					url:    targetURL,
					headers: []Header{{
						Key:   headerURL,
						Value: parentPath,
					}},
					bypassMode: ModeHeadersURL,
				}
			}

			// Fourth variant: full URL with parent path
			if strings.Contains(strings.ToLower(headerURL), "url") ||
				strings.Contains(strings.ToLower(headerURL), "refer") {
				fullURL := baseURL + parentPath
				if !seen[headerURL+fullURL] {
					seen[headerURL+fullURL] = true
					jobs <- PayloadJob{
						method: "GET",
						url:    targetURL,
						headers: []Header{{
							Key:   headerURL,
							Value: fullURL,
						}},
						bypassMode: ModeHeadersURL,
					}
				}
			}
		}
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

	seen := make(map[string]bool)

	for _, headerPort := range headerPorts {
		// Skip empty lines
		if headerPort == "" {
			continue
		}

		for _, port := range internalPorts {
			if !seen[headerPort+port] {
				seen[headerPort+port] = true
				jobs <- PayloadJob{
					method: "GET",
					url:    targetURL,
					headers: []Header{{
						Key:   headerPort,
						Value: port,
					}},
					bypassMode: ModeHeadersPort,
				}
			}
		}
	}
}
