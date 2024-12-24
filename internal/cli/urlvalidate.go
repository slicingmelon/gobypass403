package cli

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/slicingmelon/go-bypass-403/internal/engine/recon"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/slicingmelon/go-rawurlparser"
)

// URLProcessor handles URL processing and validation
type URLRecon struct {
	opts         *Options
	reconService *recon.ReconService
	reconCache   *recon.ReconCache
	logger       GB403Logger.ILogger
}

func NewURLRecon(opts *Options, logger GB403Logger.ILogger) *URLRecon {
	reconService := recon.NewReconService()
	return &URLRecon{
		opts:         opts,
		reconService: reconService,
		reconCache:   reconService.GetCache(),
		logger:       logger,
	}
}

// ProcessURLs handles URL collection and probing
func (p *URLRecon) ProcessURLs() ([]string, error) {
	// First, do recon on the substitute hosts if provided
	if p.opts.SubstituteHostsFile != "" {
		err := p.readAndReconHosts()
		if err != nil {
			return nil, err
		}
		p.logger.LogInfo("Completed reconnaissance for substitute hosts")
	}

	// Now collect URLs (which will use the populated cache)
	urls, err := p.collectURLs()
	if err != nil {
		return nil, err
	}

	// Finally do recon on the actual target URLs
	p.logger.LogInfo("Starting URL validation for %d URLs", len(urls))
	if err := p.reconService.Run(urls); err != nil {
		return nil, fmt.Errorf("error during URL probing: %v", err)
	}

	return urls, nil
}

// collectURLs gathers URLs from all configured sources
func (p *URLRecon) collectURLs() ([]string, error) {
	var urls []string
	var err error

	// Process single URL with optional substitute hosts
	if p.opts.URL != "" {
		if p.opts.SubstituteHostsFile != "" {
			return p.processWithSubstituteHosts(p.opts.URL)
		}
		// Expand single URL for available schemes
		urls, err = p.expandURLSchemes(p.opts.URL)
		if err != nil {
			return nil, err
		}
	}

	// Process URLs from file
	if p.opts.URLsFile != "" {
		fileURLs, err := p.readURLsFromFile()
		if err != nil {
			return nil, err
		}
		// Expand each URL from file
		for _, url := range fileURLs {
			expanded, err := p.expandURLSchemes(url)
			if err != nil {
				p.logger.LogError("Error expanding URL %s: %v", url, err)
				continue
			}
			urls = append(urls, expanded...)
		}
	}

	if len(urls) == 0 {
		return nil, fmt.Errorf("no URLs provided")
	}

	return urls, nil
}

// readURLsFromFile reads URLs from the specified file
func (p *URLRecon) readURLsFromFile() ([]string, error) {
	content, err := os.ReadFile(p.opts.URLsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read URLs file: %v", err)
	}

	var urls []string
	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			urls = append(urls, line)
		}
	}

	return urls, nil
}

// processWithSubstituteHosts handles URL substitution with hosts from file
func (p *URLRecon) processWithSubstituteHosts(targetURL string) ([]string, error) {
	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %v", err)
	}

	originalPathAndQuery := parsedURL.Path
	if parsedURL.Query != "" {
		originalPathAndQuery += "?" + parsedURL.Query
	}

	content, err := os.ReadFile(p.opts.SubstituteHostsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read substitute hosts file: %v", err)
	}

	var urls []string
	for _, host := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}

		// Extract clean hostname without scheme
		cleanHost := host
		if strings.Contains(host, "://") {
			parsed, err := rawurlparser.RawURLParse(host)
			if err != nil {
				p.logger.LogVerbose("Skipping invalid host URL: %s - %v", host, err)
				continue
			}
			cleanHost = parsed.Host
		}

		// Check recon cache for available schemes
		result, err := p.reconCache.Get(cleanHost)
		if err != nil || result == nil {
			p.logger.LogVerbose("No cache data for host %s, skipping", cleanHost)
			continue
		}

		// Generate URLs only for schemes that are available
		for scheme := range result.IPv4Services {
			urls = append(urls, fmt.Sprintf("%s://%s%s", scheme, cleanHost, originalPathAndQuery))
		}
		for scheme := range result.IPv6Services {
			urls = append(urls, fmt.Sprintf("%s://%s%s", scheme, cleanHost, originalPathAndQuery))
		}
	}

	if len(urls) == 0 {
		return nil, fmt.Errorf("no valid URLs generated from substitute hosts file")
	}

	return urls, nil
}

// Helper methods for URL processing and validation
func (p *URLRecon) getPathAndQuery(parsedURL *url.URL) string {
	path := parsedURL.Path
	if parsedURL.RawQuery != "" {
		path += "?" + parsedURL.RawQuery
	}
	return path
}

func (p *URLRecon) constructBaseURL(scheme, host, port string) string {
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		return fmt.Sprintf("%s://%s", scheme, host)
	}
	return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}

// GetReconCache returns the recon cache for use by other components
func (p *URLRecon) GetReconCache() *recon.ReconCache {
	return p.reconCache
}

func (p *URLRecon) readAndReconHosts() error {
	content, err := os.ReadFile(p.opts.SubstituteHostsFile)
	if err != nil {
		return fmt.Errorf("failed to read hosts file: %v", err)
	}

	var hosts []string
	for _, host := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		if host = strings.TrimSpace(host); host != "" {
			// Extract clean hostname without scheme
			cleanHost := host
			if strings.Contains(host, "://") {
				parsed, err := rawurlparser.RawURLParse(host)
				if err != nil {
					p.logger.LogVerbose("Skipping invalid host URL: %s - %v", host, err)
					continue
				}
				cleanHost = parsed.Host
			}
			hosts = append(hosts, cleanHost)
		}
	}

	if len(hosts) == 0 {
		return fmt.Errorf("no valid hosts found in substitute hosts file")
	}

	// Run recon on clean hostnames
	for _, host := range hosts {
		if err := p.reconService.Run([]string{host}); err != nil {
			p.logger.LogError("Failed recon for host %s: %v", host, err)
		}
	}

	return nil
}

func (p *URLRecon) expandURLSchemes(targetURL string) ([]string, error) {
	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}

	host := parsedURL.Host
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}

	pathAndQuery := parsedURL.Path
	if parsedURL.Query != "" {
		pathAndQuery += "?" + parsedURL.Query
	}

	result, err := p.reconCache.Get(host)
	if err != nil || result == nil {
		return []string{targetURL}, nil
	}

	urls := make([]string, 0, 2) // Most hosts have max 2 schemes: http/https

	// Add both schemes if they exist in either IPv4 or IPv6
	if len(result.IPv4Services["http"]) > 0 || len(result.IPv6Services["http"]) > 0 {
		urls = append(urls, fmt.Sprintf("http://%s%s", parsedURL.Host, pathAndQuery))
	}
	if len(result.IPv4Services["https"]) > 0 || len(result.IPv6Services["https"]) > 0 {
		urls = append(urls, fmt.Sprintf("https://%s%s", parsedURL.Host, pathAndQuery))
	}

	p.logger.LogVerbose("Found %d schemes for %s", len(urls), host)
	return urls, nil
}
