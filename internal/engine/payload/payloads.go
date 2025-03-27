package payload

import (
	"fmt"
	"strings"

	"github.com/slicingmelon/go-bypass-403/internal/engine/recon"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/slicingmelon/go-rawurlparser"
)

// BypassModuleRegistry contains all available bypass modules
// This is used for debug token indexing and is independent of which modules are enabled for a scan
var BypassModulesRegistry = []string{
	"dumb_check",
	"mid_paths",
	"end_paths",
	"case_substitution",
	"char_encode",
	"http_headers_scheme",
	"http_headers_ip",
	"http_headers_port",
	"http_headers_url",
	"http_host",
	"unicode_path_normalization",
}

type PayloadGenerator struct {
}

type BypassPayload struct {
	OriginalURL  string    // store it as we might need it
	Scheme       string    // this gets updated
	Method       string    // this gets updated
	Host         string    // this gets updated
	RawURI       string    // this gets updated, represents everything that goes into the first line of the request u
	Headers      []Headers // all headers as result of various payload generators
	BypassModule string    // always gets updated
	PayloadToken string    // always gets updated
}

func NewPayloadGenerator() *PayloadGenerator {
	return &PayloadGenerator{}
}

type Headers struct {
	Header string
	Value  string
}

func (pg *PayloadGenerator) GenerateDumbCheckPayload(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
		return allJobs
	}

	// Extract path and query
	rawURI := parsedURL.Path
	if parsedURL.Query != "" {
		rawURI += "?" + parsedURL.Query
	}

	// Just one job with the original URL
	job := BypassPayload{
		OriginalURL:  targetURL,
		Method:       "GET",
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		RawURI:       rawURI,
		BypassModule: bypassModule,
	}

	// Generate token with only the necessary components
	job.PayloadToken = GeneratePayloadToken(job)

	allJobs = append(allJobs, job)

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated 1 payload for %s\n", targetURL)
	return allJobs
}

func (pg *PayloadGenerator) GenerateMidPathsPayloads(targetURL string, bypassModule string) []BypassPayload {
	var jobs []BypassPayload
	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
		return jobs
	}

	payloads, err := ReadPayloadsFromFile("internal_midpaths.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read midpaths payloads: %v\n", err)
		return jobs
	}

	path := parsedURL.Path
	if path == "" {
		path = "/"
	}

	// Extract query string if it exists
	query := ""
	if parsedURL.Query != "" {
		query = "?" + parsedURL.Query
	}

	slashCount := strings.Count(path, "/")
	if slashCount == 0 {
		slashCount = 1
	}

	// map[rawURI]struct{} - we only need unique RawURIs
	uniquePaths := make(map[string]struct{})

	for idxSlash := 0; idxSlash < slashCount; idxSlash++ {
		for _, payload := range payloads {
			// Post-slash variants (always)
			pathPost := ReplaceNth(path, "/", "/"+payload, idxSlash+1)
			if pathPost != path { // Only add if replacement was successful
				uniquePaths[pathPost+query] = struct{}{}
				uniquePaths["/"+pathPost+query] = struct{}{}
			}

			// Pre-slash variants only if idxSlash > 1
			if idxSlash > 1 {
				pathPre := ReplaceNth(path, "/", payload+"/", idxSlash+1)
				if pathPre != path { // Only add if replacement was successful
					uniquePaths[pathPre+query] = struct{}{}
					uniquePaths["/"+pathPre+query] = struct{}{}
				}
			}
		}
	}

	// Convert unique paths to PayloadJobs
	for rawURI := range uniquePaths {
		job := BypassPayload{
			OriginalURL:  targetURL,
			Method:       "GET",
			Scheme:       parsedURL.Scheme,
			Host:         parsedURL.Host,
			RawURI:       rawURI,
			BypassModule: bypassModule,
		}

		// Generate token with only the necessary components
		job.PayloadToken = GeneratePayloadToken(job)

		jobs = append(jobs, job)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(jobs), targetURL)
	return jobs
}

func (pg *PayloadGenerator) GenerateEndPathsPayloads(targetURL string, bypassModule string) []BypassPayload {
	var jobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
		return jobs
	}

	payloads, err := ReadPayloadsFromFile("internal_endpaths.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read endpaths payloads: %v\n", err)
		return jobs
	}

	basePath := parsedURL.Path
	separator := ""
	if basePath != "/" && !strings.HasSuffix(basePath, "/") {
		separator = "/"
	}

	// Extract query string if it exists
	query := ""
	if parsedURL.Query != "" {
		query = "?" + parsedURL.Query
	}

	// map[rawURI]struct{} - we only need unique RawURIs
	uniquePaths := make(map[string]struct{})

	for _, payload := range payloads {
		// First variant - 'url/suffix'
		rawURI := basePath + separator + payload + query
		uniquePaths[rawURI] = struct{}{}

		// Second variant - 'url/suffix/'
		rawURIWithSlash := basePath + separator + payload + "/" + query
		uniquePaths[rawURIWithSlash] = struct{}{}

		// Only if basePath is not "/" and payload doesn't start with a letter
		if basePath != "/" {
			if !isLetter(payload[0]) {
				// Third variant - Add 'suffix'
				rawURISuffix := basePath + payload + query
				uniquePaths[rawURISuffix] = struct{}{}

				// Fourth variant - Add 'suffix/'
				rawURISuffixSlash := basePath + payload + "/" + query
				uniquePaths[rawURISuffixSlash] = struct{}{}
			}
		}
	}

	// Convert unique paths to PayloadJobs
	for rawURI := range uniquePaths {
		job := BypassPayload{
			OriginalURL:  targetURL,
			Method:       "GET",
			Scheme:       parsedURL.Scheme,
			Host:         parsedURL.Host,
			RawURI:       rawURI,
			BypassModule: bypassModule,
		}

		job.PayloadToken = GeneratePayloadToken(job)

		jobs = append(jobs, job)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(jobs), targetURL)
	return jobs
}

func (pg *PayloadGenerator) GenerateHeaderIPPayloads(targetURL string, bypassModule string, spoofHeader string, spoofIP string) []BypassPayload {
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
	if spoofHeader != "" {
		customHeaders := strings.Split(spoofHeader, ",")
		for _, header := range customHeaders {
			header = strings.TrimSpace(header)
			if header != "" {
				headerNames = append(headerNames, header)
			}
		}
		GB403Logger.Verbose().BypassModule(bypassModule).Msgf("Added [%s] custom headers from -spoof-header\n", strings.Join(customHeaders, ","))
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

func (pg *PayloadGenerator) GenerateCaseSubstitutionPayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
		return allJobs
	}

	basePath := parsedURL.Path

	// Extract query string if it exists
	query := ""
	if parsedURL.Query != "" {
		query = "?" + parsedURL.Query
	}

	// map[rawURI]struct{} - we only need unique RawURIs
	uniquePaths := make(map[string]struct{})

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

			// Add query to the case-modified path
			uniquePaths[newPath+query] = struct{}{}
		}
	}

	// Convert to PayloadJobs
	for rawURI := range uniquePaths {
		job := BypassPayload{
			OriginalURL:  targetURL,
			Method:       "GET",
			Scheme:       parsedURL.Scheme,
			Host:         parsedURL.Host,
			RawURI:       rawURI,
			BypassModule: bypassModule,
		}

		job.PayloadToken = GeneratePayloadToken(job)

		allJobs = append(allJobs, job)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(allJobs), targetURL)
	return allJobs
}

func (pg *PayloadGenerator) GenerateCharEncodePayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
		return allJobs
	}

	basePath := parsedURL.Path

	// Extract query string if it exists
	query := ""
	if parsedURL.Query != "" {
		query = "?" + parsedURL.Query
	}

	// Create three separate maps for different encoding levels
	singlePaths := make(map[string]struct{})
	doublePaths := make(map[string]struct{})
	triplePaths := make(map[string]struct{})

	// Base job template
	baseJob := BypassPayload{
		OriginalURL:  targetURL,
		Method:       "GET",
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		BypassModule: bypassModule,
	}

	// Find all letter positions
	for i, char := range basePath {
		if isLetter(byte(char)) {
			// Single URL encoding
			encoded := fmt.Sprintf("%%%02x", char)
			singleEncoded := basePath[:i] + encoded + basePath[i+1:]
			singlePaths[singleEncoded+query] = struct{}{}

			// Double URL encoding
			doubleEncoded := basePath[:i] + "%25" + encoded[1:] + basePath[i+1:]
			doublePaths[doubleEncoded+query] = struct{}{}

			// Triple URL encoding
			tripleEncoded := basePath[:i] + "%2525" + encoded[1:] + basePath[i+1:]
			triplePaths[tripleEncoded+query] = struct{}{}
		}
	}

	// Helper function to create jobs
	createJobs := func(paths map[string]struct{}, moduleType string) {
		for rawURI := range paths {
			job := baseJob
			job.RawURI = rawURI
			job.BypassModule = moduleType
			job.PayloadToken = GeneratePayloadToken(job)
			allJobs = append(allJobs, job)
		}
	}

	// Create jobs for each encoding level
	createJobs(singlePaths, "char_encode")
	createJobs(doublePaths, "char_encode_double")
	createJobs(triplePaths, "char_encode_triple")

	totalJobs := len(singlePaths) + len(doublePaths) + len(triplePaths)
	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", totalJobs, targetURL)
	return allJobs
}

func (pg *PayloadGenerator) GenerateHeaderSchemePayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

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

	// Handle special headers with "on" value
	specialHeaders := map[string]struct{}{
		"Front-End-Https":   {},
		"X-Forwarded-HTTPS": {},
		"X-Forwarded-SSL":   {},
	}

	for _, headerScheme := range headerSchemes {
		if _, isSpecial := specialHeaders[headerScheme]; isSpecial {
			job := baseJob
			job.Headers = []Headers{{
				Header: headerScheme,
				Value:  "on",
			}}
			job.PayloadToken = GeneratePayloadToken(job)
			allJobs = append(allJobs, job)
			continue
		}

		// Handle other headers
		for _, protoScheme := range protoSchemes {
			job := baseJob
			if headerScheme == "Forwarded" {
				job.Headers = []Headers{{
					Header: headerScheme,
					Value:  fmt.Sprintf("proto=%s", protoScheme),
				}}
			} else {
				job.Headers = []Headers{{
					Header: headerScheme,
					Value:  protoScheme,
				}}
			}

			job.PayloadToken = GeneratePayloadToken(job)
			allJobs = append(allJobs, job)
		}
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(allJobs), targetURL)
	return allJobs
}

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

func (pg *PayloadGenerator) GenerateHeaderPortPayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

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

	for _, headerPort := range headerPorts {
		if headerPort == "" {
			continue
		}

		// Handle internal ports
		for _, port := range internalPorts {
			job := baseJob
			job.Headers = []Headers{{
				Header: headerPort,
				Value:  port,
			}}
			job.PayloadToken = GeneratePayloadToken(job)
			allJobs = append(allJobs, job)
		}
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(allJobs), targetURL)
	return allJobs
}

func (pg *PayloadGenerator) GenerateHostHeaderPayloads(targetURL string, bypassModule string, reconCache *recon.ReconCache) []BypassPayload {
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
	probeCacheResult, err := reconCache.Get(parsedURL.Hostname)
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

	GB403Logger.Verbose().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(allJobs), targetURL)
	return allJobs
}

/*
JS code used to fuzz unicode path chars

const charsToCheck = ["\\", "/", ".", ":", "%", "~", "*", "<", ">", "|", "@", "!", "#", "+", "{", "}", "[", "]", ";", ",", "'", "\""];
const normalizationForms = ["NFKC", "NFC", "NFD", "NFKD"];

const normalizedMatches = new Set();

// Loop through all code points (from 0x7f upwards)

	for (let i = 0x7f; i <= 0x10FFFF; i++) {
	    const char = String.fromCodePoint(i);

	    if (i > 0x7f) {
	        normalizationForms.forEach(form => {
	            const normalized = char.normalize(form);

	            for (let charToCheck of charsToCheck) {
	                if (charToCheck === normalized) {
	                    normalizedMatches.add(`${char}(${form})=${charToCheck}`);
	                }
	            }
	        });
	    }
	}

normalizedMatches.forEach(match => console.log(match));
*/
func (pg *PayloadGenerator) GenerateUnicodePathNormalizationsPayloads(targetURL string, bypassModule string) []BypassPayload {
	var jobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL: %v\n", err)
		return jobs
	}

	path := parsedURL.Path
	if path == "" {
		path = "/"
	}

	// Extract query string if it exists
	query := ""
	if parsedURL.Query != "" {
		query = "?" + parsedURL.Query
	}

	// Read Unicode mappings
	unicodeMappings, err := ReadPayloadsFromFile("unicode_path_chars.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read unicode path chars: %v\n", err)
		return jobs
	}

	// Build character mapping for '.' and '/'
	targetChars := map[rune]bool{'.': true, '/': true}
	charMap := make(map[rune][]string)

	for _, mapping := range unicodeMappings {
		parts := strings.Split(mapping, "=")
		if len(parts) != 2 {
			continue
		}
		asciiChar := []rune(parts[1])[0]
		if !targetChars[asciiChar] {
			continue
		}
		unicodeChar := strings.Split(parts[0], "(")[0]
		charMap[asciiChar] = append(charMap[asciiChar], unicodeChar)
	}

	baseJob := BypassPayload{
		OriginalURL:  targetURL,
		Method:       "GET",
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		BypassModule: bypassModule,
	}

	uniquePaths := make(map[string]struct{})

	// Helper to add both Unicode and URL-encoded versions
	addPathVariants := func(path string) {
		// Append query to the modified path
		pathWithQuery := path + query

		if _, exists := uniquePaths[pathWithQuery]; !exists {
			uniquePaths[pathWithQuery] = struct{}{}
			job := baseJob
			job.RawURI = pathWithQuery
			job.PayloadToken = GeneratePayloadToken(job)
			jobs = append(jobs, job)
		}
	}

	// Find all positions of '.' and '/'
	type CharPosition struct {
		char     rune
		position int
	}
	var positions []CharPosition
	for i, char := range path {
		if targetChars[char] {
			positions = append(positions, CharPosition{char: char, position: i})
		}
	}

	// 1. Single character replacements
	for _, pos := range positions {
		unicodeChars := charMap[pos.char]
		for _, unicodeChar := range unicodeChars {
			// Create Unicode version
			pathRunes := []rune(path)
			pathRunes[pos.position] = []rune(unicodeChar)[0]
			unicodePath := string(pathRunes)
			addPathVariants(unicodePath)

			// Create URL-encoded version
			encodedChar := URLEncodeAll(unicodeChar)
			encodedPath := path[:pos.position] + encodedChar + path[pos.position+1:]
			addPathVariants(encodedPath)
		}
	}

	// 2. Replace all occurrences of each character
	for char := range targetChars {
		if unicodeChars, ok := charMap[char]; ok {
			for _, unicodeChar := range unicodeChars {
				// Replace all occurrences with Unicode
				var unicodePath strings.Builder
				var encodedPath strings.Builder
				lastPos := 0

				for i, c := range path {
					if c == char {
						unicodePath.WriteString(path[lastPos:i])
						unicodePath.WriteString(unicodeChar)

						encodedPath.WriteString(path[lastPos:i])
						encodedPath.WriteString(URLEncodeAll(unicodeChar))

						lastPos = i + 1
					}
				}
				unicodePath.WriteString(path[lastPos:])
				encodedPath.WriteString(path[lastPos:])

				addPathVariants(unicodePath.String())
				addPathVariants(encodedPath.String())
			}
		}
	}

	GB403Logger.Debug().BypassModule(bypassModule).
		Msgf("Generated %d unicode normalization payloads for %s\n", len(jobs), targetURL)
	return jobs
}

// func (pg *PayloadGenerator) GenerateUnicodePathNormalizationsPayloads(targetURL string, bypassModule string) []BypassPayload {
// 	var jobs []BypassPayload

// 	// 1. Get midpaths payloads first
// 	midPathsPayloads := pg.GenerateMidPathsPayloads(targetURL, "mid_paths")

// 	// 2. Read Unicode mappings
// 	unicodeMappings, err := ReadPayloadsFromFile("unicode_path_chars.lst")
// 	if err != nil {
// 		GB403Logger.Error().Msgf("Failed to read unicode path chars: %v\n", err)
// 		return jobs
// 	}

// 	// 3. Build character mapping for '.' and '/'
// 	targetChars := map[rune]bool{'.': true, '/': true}
// 	charMap := make(map[rune][]string)

// 	for _, mapping := range unicodeMappings {
// 		parts := strings.Split(mapping, "=")
// 		if len(parts) != 2 {
// 			continue
// 		}
// 		asciiChar := []rune(parts[1])[0]
// 		if !targetChars[asciiChar] {
// 			continue
// 		}
// 		unicodeChar := strings.Split(parts[0], "(")[0]
// 		charMap[asciiChar] = append(charMap[asciiChar], unicodeChar)
// 	}

// 	// 4. Filter midpaths payloads to only those containing dots or slashes
// 	var filteredPayloads []BypassPayload
// 	for _, payload := range midPathsPayloads {
// 		if containsAny(payload.RawURI, []rune{'.', '/'}) {
// 			filteredPayloads = append(filteredPayloads, payload)
// 		}
// 	}

// 	// 5. Track unique paths to avoid duplicates
// 	uniquePaths := make(map[string]struct{})

// 	// 6. Process each filtered payload
// 	for _, origPayload := range filteredPayloads {
// 		path := origPayload.RawURI

// 		// Find all positions of '.' and '/'
// 		type CharPosition struct {
// 			char     rune
// 			position int
// 		}
// 		var positions []CharPosition
// 		for i, char := range path {
// 			if targetChars[char] {
// 				positions = append(positions, CharPosition{char: char, position: i})
// 			}
// 		}

// 		// Single character replacements
// 		for _, pos := range positions {
// 			unicodeChars := charMap[pos.char]
// 			for _, unicodeChar := range unicodeChars {
// 				// Create Unicode version
// 				pathRunes := []rune(path)
// 				pathRunes[pos.position] = []rune(unicodeChar)[0]
// 				unicodePath := string(pathRunes)

// 				if _, exists := uniquePaths[unicodePath]; !exists {
// 					uniquePaths[unicodePath] = struct{}{}

// 					// Create a new job based on the original payload
// 					job := BypassPayload{
// 						OriginalURL:  origPayload.OriginalURL,
// 						Method:       origPayload.Method,
// 						Scheme:       origPayload.Scheme,
// 						Host:         origPayload.Host,
// 						RawURI:       unicodePath,
// 						Headers:      origPayload.Headers,
// 						BypassModule: bypassModule,
// 					}
// 					job.PayloadToken = GeneratePayloadToken(job)
// 					jobs = append(jobs, job)
// 				}

// 				// Create URL-encoded version
// 				encodedChar := URLEncodeAll(unicodeChar)
// 				encodedPath := path[:pos.position] + encodedChar + path[pos.position+1:]

// 				if _, exists := uniquePaths[encodedPath]; !exists {
// 					uniquePaths[encodedPath] = struct{}{}

// 					// Create a new job based on the original payload
// 					job := BypassPayload{
// 						OriginalURL:  origPayload.OriginalURL,
// 						Method:       origPayload.Method,
// 						Scheme:       origPayload.Scheme,
// 						Host:         origPayload.Host,
// 						RawURI:       encodedPath,
// 						Headers:      origPayload.Headers,
// 						BypassModule: bypassModule,
// 					}
// 					job.PayloadToken = GeneratePayloadToken(job)
// 					jobs = append(jobs, job)
// 				}
// 			}
// 		}
// 	}

// 	GB403Logger.Debug().BypassModule(bypassModule).
// 		Msgf("Generated %d unicode normalization payloads for %s\n", len(jobs), targetURL)
// 	return jobs
// }

// // Helper function to check if a string contains any of the given runes
// func containsAny(s string, chars []rune) bool {
// 	for _, c := range s {
// 		for _, t := range chars {
// 			if c == t {
// 				return true
// 			}
// 		}
// 	}
// 	return false
// }
