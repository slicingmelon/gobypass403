/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/slicingmelon/go-rawurlparser"
	"github.com/slicingmelon/gobypass403/core/engine/recon"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

// URLProcessor handles URL processing and validation
type URLRecon struct {
	opts         *CliOptions
	reconService *recon.ReconService
}

func NewURLRecon(opts *CliOptions) *URLRecon {
	reconService := recon.NewReconService()
	return &URLRecon{
		opts:         opts,
		reconService: reconService,
	}
}

// ProcessURLs handles URL collection and probing
func (p *URLRecon) ProcessURLs() ([]string, error) {
	// First collect all URLs we need to process
	var urlsToProbe []string

	// If single URL is provided
	if p.opts.URL != "" {
		urlsToProbe = append(urlsToProbe, p.opts.URL)
	}

	// If URLs file is provided
	if p.opts.URLsFile != "" {
		fileURLs, err := p.readURLsFromFile(p.opts.URLsFile)
		if err != nil {
			return nil, err
		}

		urlsToProbe = append(urlsToProbe, fileURLs...)
	}

	if len(urlsToProbe) == 0 {
		return nil, fmt.Errorf("no URLs found to process")
	}

	// Do recon on all URLs to populate the cache
	GB403Logger.Info().Msgf("Starting URL validation for %d URLs", len(urlsToProbe))
	if err := p.reconService.Run(urlsToProbe); err != nil {
		return nil, fmt.Errorf("error during URL probing: %v", err)
	}

	// Then collect processed URLs using the populated cache
	urls, err := p.collectURLs()
	if err != nil {
		return nil, err
	}

	return urls, nil
}

// collectURLs gathers URLs from all configured sources
func (p *URLRecon) collectURLs() ([]string, error) {
	var urls []string
	//var err error

	// Process single URL with optional substitute hosts
	if p.opts.URL != "" {
		// First expand the original URL for available schemes
		originalURLs, err := p.expandURLSchemes(p.opts.URL)
		if err != nil {
			return nil, err
		}
		urls = append(urls, originalURLs...)

		// Then process substitute hosts if provided
		if p.opts.SubstituteHostsFile != "" {
			substituteURLs, err := p.processWithSubstituteHosts(p.opts.URL)
			if err != nil {
				GB403Logger.Error().Msgf("Error processing substitute hosts: %v", err)
				// Continue with original URL even if substitute hosts fail
			} else {
				urls = append(urls, substituteURLs...)
			}
		}
	}

	// Process URLs from file (if provided)
	if p.opts.URLsFile != "" {
		fileURLs, err := p.readURLsFromFile(p.opts.URLsFile)
		if err != nil {
			return nil, err
		}
		// Expand each URL from file
		for _, url := range fileURLs {
			expanded, err := p.expandURLSchemes(url)
			if err != nil {
				GB403Logger.Error().Msgf("Error expanding URL %s: %v", url, err)
				continue
			}
			urls = append(urls, expanded...)
		}
	}

	if len(urls) == 0 {
		return nil, fmt.Errorf("no valid URLs to process")
	}

	return urls, nil
}

// readURLsFromFile reads URLs from the specified file
func (p *URLRecon) readURLsFromFile(urlsFile string) ([]string, error) {
	file, err := os.Open(urlsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open URLs file: %v", err)

	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			urls = append(urls, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading URLs file: %v", err)
	}

	return urls, nil
}

// processWithSubstituteHosts handles URL substitution with hosts from file
func (p *URLRecon) processWithSubstituteHosts(targetURL string) ([]string, error) {
	data, err := os.ReadFile(p.opts.SubstituteHostsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read substitute hosts file: %v", err)
	}

	// Collect all hosts first
	var hosts []string
	for _, host := range strings.Split(string(data), "\n") {
		if host = strings.TrimSpace(host); host != "" {
			cleanHost := host
			if strings.Contains(host, "://") {
				parsed, err := rawurlparser.RawURLParse(host)
				if err != nil {
					GB403Logger.Verbose().Msgf("Skipping invalid host URL: %s - %v", host, err)
					continue
				}
				cleanHost = parsed.Host
			}
			hosts = append(hosts, cleanHost)
		}
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("no valid hosts found in substitute hosts file")
	}

	// Process all hosts in a single Run call to utilize parallelism
	GB403Logger.Info().Msgf("Processing %d substitute hosts in parallel", len(hosts))
	if err := p.reconService.Run(hosts); err != nil {
		GB403Logger.Error().Msgf("Some errors occurred during host recon: %v", err)
		// Continue anyway, we'll filter valid hosts below
	}

	// Now check which hosts passed recon
	var validHosts []string
	for _, host := range hosts {
		result, err := p.reconService.GetReconCache().Get(host)
		if err == nil && result != nil && (len(result.IPv4Services) > 0 || len(result.IPv6Services) > 0) {
			validHosts = append(validHosts, host)
		} else {
			GB403Logger.Verbose().Msgf("Host %s failed recon or has no services - skipping", host)
		}
	}

	if len(validHosts) == 0 {
		return nil, fmt.Errorf("no hosts passed recon checks")
	}

	// The rest of your code remains the same
	var urls []string
	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %v", err)
	}

	pathAndQuery := parsedURL.Path
	if parsedURL.Query != "" {
		pathAndQuery += "?" + parsedURL.Query
	}

	// Using validHosts to ensure we only process valid ones
	for _, host := range validHosts {
		expandedURLs, err := p.expandURLSchemes(fmt.Sprintf("http://%s%s", host, pathAndQuery))
		if err != nil {
			GB403Logger.Error().Msgf("Failed to expand URL schemes for host %s: %v", host, err)
			continue
		}
		urls = append(urls, expandedURLs...)
	}

	return urls, nil
}

func (p *URLRecon) expandURLSchemes(targetURL string) ([]string, error) {
	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}

	host := parsedURL.Host
	result, err := p.reconService.GetReconCache().Get(host)
	if err != nil || result == nil {
		GB403Logger.Verbose().Msgf("No cache result for %s: %v", host, err)
		return nil, fmt.Errorf("host %s failed recon checks", host)
	}

	// Debug logging
	GB403Logger.Verbose().Msgf("Cache result for %s:", host)
	GB403Logger.Verbose().Msgf("IPv4 Services: %+v", result.IPv4Services)
	GB403Logger.Verbose().Msgf("IPv6 Services: %+v", result.IPv6Services)

	// Get unique schemes from both IPv4 and IPv6 services
	schemes := make(map[string]bool)
	for scheme := range result.IPv4Services {
		schemes[scheme] = true
		GB403Logger.Verbose().Msgf("Found IPv4 scheme: %s", scheme)
	}
	for scheme := range result.IPv6Services {
		schemes[scheme] = true
	}

	// If strict scheme is enabled, only use the original scheme if it's supported
	if p.opts.StrictScheme {
		originalScheme := parsedURL.Scheme
		if originalScheme == "" {
			return nil, fmt.Errorf("original URL has no scheme and strict-scheme is enabled")
		}

		if !schemes[originalScheme] {
			GB403Logger.Verbose().Msgf("Original scheme '%s' not supported by host %s (supported: %v)",
				originalScheme, host, getSchemesList(schemes))
			return nil, fmt.Errorf("original scheme '%s' not supported by host %s", originalScheme, host)
		}

		// Only return URL with original scheme
		pathAndQuery := parsedURL.Path
		if parsedURL.Query != "" {
			pathAndQuery += "?" + parsedURL.Query
		}

		GB403Logger.Verbose().Msgf("Strict scheme mode: using only original scheme '%s' for %s", originalScheme, host)
		return []string{fmt.Sprintf("%s://%s%s", originalScheme, host, pathAndQuery)}, nil
	}

	// Normal behavior: generate URLs for each unique scheme
	urls := make([]string, 0, len(schemes))
	pathAndQuery := parsedURL.Path
	if parsedURL.Query != "" {
		pathAndQuery += "?" + parsedURL.Query
	}

	for scheme := range schemes {
		urls = append(urls, fmt.Sprintf("%s://%s%s", scheme, host, pathAndQuery))
	}

	return urls, nil
}

// Helper function to convert schemes map to slice for logging
func getSchemesList(schemes map[string]bool) []string {
	var list []string
	for scheme := range schemes {
		list = append(list, scheme)
	}
	return list
}
