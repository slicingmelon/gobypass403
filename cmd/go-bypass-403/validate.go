package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/utils"
	"github.com/slicingmelon/go-rawurlparser"
)

// URLProcessor handles URL validation and processing
type URLProcessor struct {
	opts          *Options
	hostsToProbe  []string
	originalPaths map[string]string
	probeService  *ProbeService
}

func NewURLProcessor(opts *Options) *URLProcessor {
	return &URLProcessor{
		opts:          opts,
		originalPaths: make(map[string]string),
		probeService:  NewProbeService(),
	}
}

// ProcessAndValidate processes and validates all options after parsing
func (o *Options) ProcessAndValidate() error {

	if err := o.validateAndProcessURLs(); err != nil {
		return err
	}

	if err := o.validateInputs(); err != nil {
		return err
	}

	if err := o.processMatchStatusCodes(); err != nil {
		return err
	}

	if err := o.validateBypassModules(); err != nil {
		return err
	}

	if err := o.setupOutputDir(); err != nil {
		return err
	}

	if err := o.processProxy(); err != nil {
		return err
	}

	o.setDefaults()
	return nil
}

// validateInputs checks URL and file inputs
func (o *Options) validateInputs() error {
	if o.URL == "" && o.URLsFile == "" {
		return fmt.Errorf("either Target URL (-u) or URLs file (-l) is required")
	}

	if o.SubstituteHostsFile != "" {
		if o.URL == "" {
			return fmt.Errorf("a target URL (-u) is required when using substitute hosts file")
		}
		if o.URLsFile != "" {
			return fmt.Errorf("cannot use both URLs file (-l) and substitute hosts file")
		}
	}
	return nil
}

// processMatchStatusCodes processes status codes string into integers
func (o *Options) processMatchStatusCodes() error {
	if o.MatchStatusCodesStr == "" {
		o.MatchStatusCodes = []int{200}
		return nil
	}

	parts := strings.Split(o.MatchStatusCodesStr, ",")
	for _, p := range strings.Fields(strings.Join(parts, " ")) {
		if code, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			if code >= 100 && code < 600 {
				o.MatchStatusCodes = append(o.MatchStatusCodes, code)
			}
		}
	}

	if len(o.MatchStatusCodes) == 0 {
		o.MatchStatusCodes = []int{200}
	}
	return nil
}

// validateBypassModules validates the bypass mode
func (o *Options) validateBypassModules() error {
	availableModes := getAvailableBypassModules()
	modes := strings.Split(o.Mode, ",")

	for _, m := range modes {
		m = strings.TrimSpace(m)
		if !availableModes[m] {
			var modeList []string
			for mode := range availableModes {
				modeList = append(modeList, mode)
			}
			sort.Strings(modeList)
			return fmt.Errorf("invalid bypass mode: %s\nAvailable modes: %s",
				m, strings.Join(modeList, ", "))
		}
	}
	return nil
}

// setupOutputDir creates and validates output directory
func (o *Options) setupOutputDir() error {
	if o.OutDir == "" {
		o.OutDir = filepath.Join(os.TempDir(), fmt.Sprintf("go-bypass-403-%x", time.Now().UnixNano()))
	}
	return os.MkdirAll(o.OutDir, 0755)
}

// processProxy validates and parses proxy URL
func (o *Options) processProxy() error {
	if o.Proxy == "" {
		return nil
	}

	parsedProxy, err := url.Parse(o.Proxy)
	if err != nil {
		return fmt.Errorf("failed to parse proxy URL: %v", err)
	}
	o.ParsedProxy = parsedProxy
	return nil
}

// validateAndProcessURLs handles all URL input validation and processing
// Update existing validateAndProcessURLs to only validate
func (o *Options) validateAndProcessURLs() error {
	// Basic input validation
	if err := o.validateInputs(); err != nil {
		return err
	}

	// Validate URL formats only, not processing
	if o.URL != "" {
		if err := o.validateSingleURL(o.URL); err != nil {
			return fmt.Errorf("invalid target URL: %v", err)
		}
	}

	if o.URLsFile != "" {
		if err := o.validateURLsFile(); err != nil {
			return err
		}
	}

	if o.SubstituteHostsFile != "" {
		if err := o.validateSubstituteHosts(); err != nil {
			return err
		}
	}

	return nil
}

// validateSingleURL validates a single URL
func (o *Options) validateSingleURL(inputURL string) error {
	parsed, err := rawurlparser.RawURLParse(inputURL)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %v", err)
	}

	if parsed.Host == "" {
		return fmt.Errorf("URL must contain a host")
	}

	return nil
}

// validateURLsFile validates the URLs file content
func (o *Options) validateURLsFile() error {
	content, err := os.ReadFile(o.URLsFile)
	if err != nil {
		return fmt.Errorf("failed to read URLs file: %v", err)
	}

	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if err := o.validateSingleURL(line); err != nil {
			return fmt.Errorf("invalid URL in file: %v", err)
		}
	}

	return nil
}

// validateSubstituteHosts validates the substitute hosts file
func (o *Options) validateSubstituteHosts() error {
	content, err := os.ReadFile(o.SubstituteHostsFile)
	if err != nil {
		return fmt.Errorf("failed to read substitute hosts file: %v", err)
	}

	for _, host := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}

		// Extract host if it's a URL
		if strings.Contains(host, "://") {
			parsed, err := rawurlparser.RawURLParse(host)
			if err != nil {
				return fmt.Errorf("invalid URL in substitute hosts file: %v", err)
			}
			host = parsed.Host
		}

		if !utils.IsIP(host) && !utils.IsDNSName(host) {
			return fmt.Errorf("invalid host in substitute file: %s", host)
		}
	}

	return nil
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

// setDefaults sets default values for options
func (o *Options) setDefaults() {
	if o.Delay <= 0 {
		o.Delay = 150
	}
	if o.Threads <= 0 {
		o.Threads = 15
	}
	if o.Timeout <= 0 {
		o.Timeout = 15
	}
}
