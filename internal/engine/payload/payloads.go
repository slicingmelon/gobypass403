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
	OriginalURL  string    // store it as we might need it
	Method       string    // this gets updated
	Scheme       string    // this gets updated
	Host         string    // this gets updated
	RawURI       string    // this gets updated, represents everything that goes into the first line of the request u
	Headers      []Headers // all headers as result of various payload generators
	BypassModule string
	PayloadToken string
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
	job := PayloadJob{
		OriginalURL:  targetURL,
		Method:       "GET",
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		RawURI:       parsedURL.Path,
		BypassModule: bypassModule,
	}

	// Generate token with only the necessary components
	job.PayloadToken = GenerateDebugToken(SeedData{
		Method: job.Method,
		Scheme: job.Scheme,
		Host:   job.Host,
		RawURI: job.RawURI,
	})

	allJobs = append(allJobs, job)

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated 1 payload for %s\n", targetURL)
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
		GB403Logger.Error().Msgf("Failed to read midpaths payloads: %v\n", err)
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

	// map[rawURI]struct{} - we only need unique RawURIs
	uniquePaths := make(map[string]struct{})

	for idxSlash := 0; idxSlash < slashCount; idxSlash++ {
		for _, payload := range payloads {
			// Post-slash variants (always)
			pathPost := ReplaceNth(path, "/", "/"+payload, idxSlash+1)
			if pathPost != path { // Only add if replacement was successful
				uniquePaths[pathPost] = struct{}{}
				uniquePaths["/"+pathPost] = struct{}{}
			}

			// Pre-slash variants only if idxSlash > 1
			if idxSlash > 1 {
				pathPre := ReplaceNth(path, "/", payload+"/", idxSlash+1)
				if pathPre != path { // Only add if replacement was successful
					uniquePaths[pathPre] = struct{}{}
					uniquePaths["/"+pathPre] = struct{}{}
				}
			}
		}
	}

	// Convert unique paths to PayloadJobs
	for rawURI := range uniquePaths {
		job := PayloadJob{
			OriginalURL:  targetURL,
			Method:       "GET",
			Scheme:       parsedURL.Scheme,
			Host:         parsedURL.Host,
			RawURI:       rawURI,
			BypassModule: bypassModule,
		}

		// Generate token with only the necessary components
		job.PayloadToken = GenerateDebugToken(SeedData{
			Method: job.Method,
			Scheme: job.Scheme,
			Host:   job.Host,
			RawURI: job.RawURI,
		})

		jobs = append(jobs, job)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(jobs), targetURL)
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
		GB403Logger.Error().Msgf("Failed to read endpaths payloads: %v\n", err)
		return jobs
	}

	basePath := parsedURL.Path
	separator := ""
	if basePath != "/" && !strings.HasSuffix(basePath, "/") {
		separator = "/"
	}

	// map[rawURI]struct{} - we only need unique RawURIs
	uniquePaths := make(map[string]struct{})

	for _, payload := range payloads {
		// First variant - 'url/suffix'
		rawURI := basePath + separator + payload
		uniquePaths[rawURI] = struct{}{}

		// Second variant - 'url/suffix/'
		rawURIWithSlash := rawURI + "/"
		uniquePaths[rawURIWithSlash] = struct{}{}

		// Only if basePath is not "/" and payload doesn't start with a letter
		if basePath != "/" {
			if !isLetter(payload[0]) {
				// Third variant - Add 'suffix'
				rawURISuffix := basePath + payload
				uniquePaths[rawURISuffix] = struct{}{}

				// Fourth variant - Add 'suffix/'
				rawURISuffixSlash := rawURISuffix + "/"
				uniquePaths[rawURISuffixSlash] = struct{}{}
			}
		}
	}

	// Convert unique paths to PayloadJobs
	for rawURI := range uniquePaths {
		job := PayloadJob{
			OriginalURL:  targetURL,
			Method:       "GET",
			Scheme:       parsedURL.Scheme,
			Host:         parsedURL.Host,
			RawURI:       rawURI,
			BypassModule: bypassModule,
		}

		job.PayloadToken = GenerateDebugToken(SeedData{
			Method: job.Method,
			Scheme: job.Scheme,
			Host:   job.Host,
			RawURI: job.RawURI,
		})

		jobs = append(jobs, job)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(jobs), targetURL)
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

	// Base job template
	baseJob := PayloadJob{
		OriginalURL:  targetURL,
		Method:       "GET",
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		RawURI:       parsedURL.Path,
		BypassModule: bypassModule,
	}

	// Special case job
	specialJob := baseJob
	specialJob.Headers = []Headers{{
		Header: "X-AppEngine-Trusted-IP-Request",
		Value:  "1",
	}}
	specialJob.PayloadToken = GenerateDebugToken(SeedData{
		Method:  specialJob.Method,
		Scheme:  specialJob.Scheme,
		Host:    specialJob.Host,
		RawURI:  specialJob.RawURI,
		Headers: specialJob.Headers,
	})
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
					job.PayloadToken = GenerateDebugToken(SeedData{
						Method:  job.Method,
						Scheme:  job.Scheme,
						Host:    job.Host,
						RawURI:  job.RawURI,
						Headers: job.Headers,
					})
					allJobs = append(allJobs, job)
				}
			} else {
				job := baseJob
				job.Headers = []Headers{{
					Header: headerName,
					Value:  ip,
				}}
				job.PayloadToken = GenerateDebugToken(SeedData{
					Method:  job.Method,
					Scheme:  job.Scheme,
					Host:    job.Host,
					RawURI:  job.RawURI,
					Headers: job.Headers,
				})
				allJobs = append(allJobs, job)
			}
		}
	}

	GB403Logger.Debug().Msgf("[%s] Generated %d payloads for %s\n", bypassModule, len(allJobs), targetURL)
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

			uniquePaths[newPath] = struct{}{}
		}
	}

	// Convert to PayloadJobs
	for rawURI := range uniquePaths {
		job := PayloadJob{
			OriginalURL:  targetURL,
			Method:       "GET",
			Scheme:       parsedURL.Scheme,
			Host:         parsedURL.Host,
			RawURI:       rawURI,
			BypassModule: bypassModule,
		}

		job.PayloadToken = GenerateDebugToken(SeedData{
			Method: job.Method,
			Scheme: job.Scheme,
			Host:   job.Host,
			RawURI: job.RawURI,
		})

		allJobs = append(allJobs, job)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(allJobs), targetURL)
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

	// Create three separate maps for different encoding levels
	singlePaths := make(map[string]struct{})
	doublePaths := make(map[string]struct{})
	triplePaths := make(map[string]struct{})

	// Base job template
	baseJob := PayloadJob{
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
			singlePaths[singleEncoded] = struct{}{}

			// Double URL encoding
			doubleEncoded := basePath[:i] + "%25" + encoded[1:] + basePath[i+1:]
			doublePaths[doubleEncoded] = struct{}{}

			// Triple URL encoding
			tripleEncoded := basePath[:i] + "%2525" + encoded[1:] + basePath[i+1:]
			triplePaths[tripleEncoded] = struct{}{}
		}
	}

	// Helper function to create jobs
	createJobs := func(paths map[string]struct{}, moduleType string) {
		for rawURI := range paths {
			job := baseJob
			job.RawURI = rawURI
			job.BypassModule = moduleType
			job.PayloadToken = GenerateDebugToken(SeedData{
				Method: job.Method,
				Scheme: job.Scheme,
				Host:   job.Host,
				RawURI: job.RawURI,
			})
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

	// Base job template
	baseJob := PayloadJob{
		OriginalURL:  targetURL,
		Method:       "GET",
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		RawURI:       parsedURL.Path,
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
			job.PayloadToken = GenerateDebugToken(SeedData{
				Method:  job.Method,
				Scheme:  job.Scheme,
				Host:    job.Host,
				RawURI:  job.RawURI,
				Headers: job.Headers,
			})
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

			job.PayloadToken = GenerateDebugToken(SeedData{
				Method:  job.Method,
				Scheme:  job.Scheme,
				Host:    job.Host,
				RawURI:  job.RawURI,
				Headers: job.Headers,
			})
			allJobs = append(allJobs, job)
		}
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(allJobs), targetURL)
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

	basePath := strings.TrimRight(parsedURL.Path, "/")
	if basePath == "" {
		basePath = "/"
	}

	// Base job template
	baseJob := PayloadJob{
		OriginalURL:  targetURL,
		Method:       "GET",
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		BypassModule: bypassModule,
	}

	for _, headerURL := range headerURLs {
		// First variant: base_path in header
		job := baseJob
		job.RawURI = "/"
		job.Headers = []Headers{{
			Header: headerURL,
			Value:  basePath,
		}}
		job.PayloadToken = GenerateDebugToken(SeedData{
			Method:  job.Method,
			Scheme:  job.Scheme,
			Host:    job.Host,
			RawURI:  job.RawURI,
			Headers: job.Headers,
		})
		allJobs = append(allJobs, job)

		// Second variant: full target URL in header
		if strings.Contains(strings.ToLower(headerURL), "url") ||
			strings.Contains(strings.ToLower(headerURL), "request") ||
			strings.Contains(strings.ToLower(headerURL), "file") {
			job := baseJob
			job.RawURI = "/"
			job.Headers = []Headers{{
				Header: headerURL,
				Value:  targetURL,
			}}
			job.PayloadToken = GenerateDebugToken(SeedData{
				Method:  job.Method,
				Scheme:  job.Scheme,
				Host:    job.Host,
				RawURI:  job.RawURI,
				Headers: job.Headers,
			})
			allJobs = append(allJobs, job)
		}

		// Parent paths variants
		parts := strings.Split(strings.Trim(basePath, "/"), "/")
		for i := len(parts) - 1; i >= 0; i-- {
			parentPath := "/" + strings.Join(parts[:i], "/")
			if parentPath == "/" {
				parentPath = "/"
			}

			// Parent path in header
			job := baseJob
			job.RawURI = parsedURL.Path
			job.Headers = []Headers{{
				Header: headerURL,
				Value:  parentPath,
			}}
			job.PayloadToken = GenerateDebugToken(SeedData{
				Method:  job.Method,
				Scheme:  job.Scheme,
				Host:    job.Host,
				RawURI:  job.RawURI,
				Headers: job.Headers,
			})
			allJobs = append(allJobs, job)

			// Full URL with parent path in header
			if strings.Contains(strings.ToLower(headerURL), "url") ||
				strings.Contains(strings.ToLower(headerURL), "refer") {
				fullURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, parentPath)
				job := baseJob
				job.RawURI = parsedURL.Path
				job.Headers = []Headers{{
					Header: headerURL,
					Value:  fullURL,
				}}
				job.PayloadToken = GenerateDebugToken(SeedData{
					Method:  job.Method,
					Scheme:  job.Scheme,
					Host:    job.Host,
					RawURI:  job.RawURI,
					Headers: job.Headers,
				})
				allJobs = append(allJobs, job)
			}
		}
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(allJobs), targetURL)
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

	// Base job template
	baseJob := PayloadJob{
		OriginalURL:  targetURL,
		Method:       "GET",
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		RawURI:       parsedURL.Path,
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
			job.PayloadToken = GenerateDebugToken(SeedData{
				Method:  job.Method,
				Scheme:  job.Scheme,
				Host:    job.Host,
				RawURI:  job.RawURI,
				Headers: job.Headers,
			})
			allJobs = append(allJobs, job)
		}
	}

	GB403Logger.Info().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(allJobs), targetURL)
	return allJobs
}

func (pg *PayloadGenerator) GenerateHostHeaderJobs(targetURL string, bypassModule string, reconCache *recon.ReconCache) []PayloadJob {
	var allJobs []PayloadJob

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
	baseJob := PayloadJob{
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
				job1.PayloadToken = GenerateDebugToken(SeedData{
					Method:  job1.Method,
					Scheme:  job1.Scheme,
					Host:    job1.Host,
					RawURI:  job1.RawURI,
					Headers: job1.Headers,
				})
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
				job2.PayloadToken = GenerateDebugToken(SeedData{
					Method:  job2.Method,
					Scheme:  job2.Scheme,
					Host:    job2.Host,
					RawURI:  job2.RawURI,
					Headers: job2.Headers,
				})
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
				job1.PayloadToken = GenerateDebugToken(SeedData{
					Method:  job1.Method,
					Scheme:  job1.Scheme,
					Host:    job1.Host,
					RawURI:  job1.RawURI,
					Headers: job1.Headers,
				})
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
				job2.PayloadToken = GenerateDebugToken(SeedData{
					Method:  job2.Method,
					Scheme:  job2.Scheme,
					Host:    job2.Host,
					RawURI:  job2.RawURI,
					Headers: job2.Headers,
				})
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
// func (pg *PayloadGenerator) GenerateUnicodePathNormalizationsJobs(targetURL string, bypassModule string) []PayloadJob {
// 	var jobs []PayloadJob

// 	// First generate midpath payloads as base
// 	midpathJobs := pg.GenerateMidPathsJobs(targetURL, bypassModule)

// 	// Read unicode normalization mappings
// 	unicodeMappings, err := ReadPayloadsFromFile("unicode_path_chars.lst")
// 	if err != nil {
// 		GB403Logger.Error().Msgf("Failed to read unicode path chars: %v", err)
// 		return jobs
// 	}

// 	// Create mapping of ASCII chars to their unicode equivalents
// 	charMap := make(map[rune][]rune)
// 	for _, mapping := range unicodeMappings {
// 		parts := strings.Split(mapping, "=")
// 		if len(parts) != 2 {
// 			continue
// 		}

// 		// Get the unicode char and its ASCII equivalent
// 		unicodeChar := []rune(strings.Split(parts[0], "(")[0])[0]
// 		asciiChar := []rune(parts[1])[0]

// 		// Add to mapping (one ASCII char can have multiple unicode equivalents)
// 		charMap[asciiChar] = append(charMap[asciiChar], unicodeChar)
// 	}

// 	// For each midpath job, create unicode variations
// 	for _, baseJob := range midpathJobs {
// 		// Add the original midpath job
// 		jobs = append(jobs, baseJob)

// 		// Create unicode variations of the RawURI
// 		path := []rune(baseJob.RawURI)
// 		for i, char := range path {
// 			// If we have unicode equivalents for this char
// 			if unicodeChars, exists := charMap[char]; exists {
// 				for _, unicodeChar := range unicodeChars {
// 					// Create new path with unicode substitution
// 					newPath := make([]rune, len(path))
// 					copy(newPath, path)
// 					newPath[i] = unicodeChar

// 					// Create new job with unicode path
// 					newRawURI := string(newPath)
// 					newFullURL := fmt.Sprintf("%s://%s%s", baseJob.Scheme, baseJob.Host, newRawURI)

// 					jobs = append(jobs, PayloadJob{
// 						OriginalURL:  baseJob.OriginalURL,
// 						Method:       "GET",
// 						Scheme:       baseJob.Scheme,
// 						Host:         baseJob.Host,
// 						RawURI:       newRawURI,
// 						FullURL:      newFullURL,
// 						BypassModule: bypassModule,
// 						PayloadToken: GenerateDebugToken(SeedData{FullURL: newFullURL}),
// 					})
// 				}
// 			}
// 		}
// 	}

// 	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(jobs), targetURL)
// 	return jobs
// }

func (pg *PayloadGenerator) GenerateUnicodePathNormalizationsJobs(targetURL string, bypassModule string) []PayloadJob {
	var jobs []PayloadJob

	// Parse URL to get path
	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL: %v", err)
		return jobs
	}

	path := parsedURL.Path
	if path == "" {
		path = "/"
	}

	// Read Unicode mappings
	unicodeMappings, err := ReadPayloadsFromFile("unicode_path_chars.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read unicode path chars: %v", err)
		return jobs
	}

	// Build character mapping - only for '.' and '/'
	targetChars := map[rune]bool{'.': true, '/': true}
	charMap := make(map[rune][]string)

	for _, mapping := range unicodeMappings {
		parts := strings.Split(mapping, "=")
		if len(parts) != 2 {
			continue
		}
		asciiChar := []rune(parts[1])[0]
		// Only process if it's a '.' or '/'
		if !targetChars[asciiChar] {
			continue
		}
		unicodeChar := []rune(strings.Split(parts[0], "(")[0])[0]
		charMap[asciiChar] = append(charMap[asciiChar], string(unicodeChar))
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

	// Base job template
	baseJob := PayloadJob{
		OriginalURL:  targetURL,
		Method:       "GET",
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		BypassModule: bypassModule,
	}

	// Helper function to create job with modified path
	createJob := func(newPath string) PayloadJob {
		job := baseJob
		job.RawURI = newPath
		job.PayloadToken = GenerateDebugToken(SeedData{
			Method: job.Method,
			Scheme: job.Scheme,
			Host:   job.Host,
			RawURI: job.RawURI,
		})
		return job
	}

	// Track unique paths to avoid duplicates
	uniquePaths := make(map[string]struct{})

	// 1. Replace each occurrence individually
	for _, pos := range positions {
		unicodeChars := charMap[pos.char]
		for _, unicodeChar := range unicodeChars {
			pathRunes := []rune(path)
			pathRunes[pos.position] = []rune(unicodeChar)[0]
			newPath := string(pathRunes)
			if _, exists := uniquePaths[newPath]; !exists {
				uniquePaths[newPath] = struct{}{}
				jobs = append(jobs, createJob(newPath))
			}
		}
	}

	// 2. Replace all occurrences of the same character together
	charGroups := make(map[rune][]int)
	for _, pos := range positions {
		charGroups[pos.char] = append(charGroups[pos.char], pos.position)
	}

	for char, positions := range charGroups {
		unicodeChars := charMap[char]
		for _, unicodeChar := range unicodeChars {
			pathRunes := []rune(path)
			for _, pos := range positions {
				pathRunes[pos] = []rune(unicodeChar)[0]
			}
			newPath := string(pathRunes)
			if _, exists := uniquePaths[newPath]; !exists {
				uniquePaths[newPath] = struct{}{}
				jobs = append(jobs, createJob(newPath))
			}
		}
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d unicode normalization payloads for %s\n", len(jobs), targetURL)
	return jobs
}
