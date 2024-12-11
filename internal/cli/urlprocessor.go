package cli

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/slicingmelon/go-bypass-403/internal/engine/probe"
	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"github.com/slicingmelon/go-rawurlparser"
)

// URLProcessor handles URL processing and validation
type URLProcessor struct {
	opts         *Options
	probeService *probe.ProbeService
	probeCache   probe.Cache
}

func NewURLProcessor(opts *Options) *URLProcessor {
	probeService := probe.NewProbeService()
	return &URLProcessor{
		opts:         opts,
		probeService: probeService,
		probeCache:   probeService.GetCache(),
	}
}

// ProcessURLs handles URL collection and probing
func (p *URLProcessor) ProcessURLs() ([]string, error) {
	// Collect URLs from input sources
	urls, err := p.collectURLs()
	if err != nil {
		return nil, err
	}

	// Probe collected URLs
	logger.Info("Starting URL validation for %d URLs", len(urls))
	if err := p.probeService.FastProbeURLs(urls); err != nil {
		return nil, fmt.Errorf("error during URL probing: %v", err)
	}

	return urls, nil
}

// collectURLs gathers URLs from all configured sources
func (p *URLProcessor) collectURLs() ([]string, error) {
	var urls []string
	var err error

	// Process single URL with optional substitute hosts
	if p.opts.URL != "" {
		if p.opts.SubstituteHostsFile != "" {
			return p.processWithSubstituteHosts(p.opts.URL)
		}
		urls = []string{p.opts.URL}
	}

	// Process URLs from file
	if p.opts.URLsFile != "" {
		urls, err = p.readURLsFromFile()
		if err != nil {
			return nil, err
		}
	}

	if len(urls) == 0 {
		return nil, fmt.Errorf("no URLs provided")
	}

	return urls, nil
}

// readURLsFromFile reads URLs from the specified file
func (p *URLProcessor) readURLsFromFile() ([]string, error) {
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
func (p *URLProcessor) processWithSubstituteHosts(targetURL string) ([]string, error) {
	// Parse original URL to keep path and query
	parsedURL, err := rawurlparser.RawURLParse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %v", err)
	}

	// Store original path and query
	originalPathAndQuery := parsedURL.Path
	if parsedURL.Query != "" {
		originalPathAndQuery += "?" + parsedURL.Query
	}

	// Read substitute hosts
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

		// If host contains scheme, extract just the host part
		if strings.Contains(host, "://") {
			parsed, err := rawurlparser.RawURLParse(host)
			if err != nil {
				logger.Debug("Skipping invalid host URL: %s - %v", host, err)
				continue
			}
			host = parsed.Host
		}

		// Construct new URL with original scheme and path
		newURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, host, originalPathAndQuery)
		urls = append(urls, newURL)
	}

	if len(urls) == 0 {
		return nil, fmt.Errorf("no valid URLs generated from substitute hosts file")
	}

	return urls, nil
}

// Helper methods for URL processing and validation
func (p *URLProcessor) getPathAndQuery(parsedURL *url.URL) string {
	path := parsedURL.Path
	if parsedURL.RawQuery != "" {
		path += "?" + parsedURL.RawQuery
	}
	return path
}

func (p *URLProcessor) constructBaseURL(scheme, host, port string) string {
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		return fmt.Sprintf("%s://%s", scheme, host)
	}
	return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}

// GetProbeCache returns the probe cache
func (p *URLProcessor) GetProbeCache() probe.Cache {
	return p.probeCache
}
