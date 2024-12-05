// config.go
package main

import (
	"net/url"
	"sync"
	"time"

	"github.com/projectdiscovery/gcache"
	"github.com/projectdiscovery/httpx/runner"
)

const (
	VERSION = "0.3.1"
)

type Config struct {
	URL                 string
	URLsFile            string
	SubstituteHostsFile string
	Mode                string
	OutDir              string
	Threads             int
	Timeout             int
	Verbose             bool
	Proxy               string
	ParsedProxy         *url.URL
	MatchStatusCodesStr string
	MatchStatusCodes    []int
	Debug               bool
	LogDebugToFile      bool `default:"false"`
	ForceHTTP2          bool
	SpoofIP             string
	SpoofHeader         string
	Delay               int
	FollowRedirects     bool
	TraceRequests       bool `default:"false"`
}

// global config
var (
	config Config
)

type Result struct {
	TargetURL       string `json:"target_url"`
	BypassMode      string `json:"bypass_mode"`
	CurlPocCommand  string `json:"curl_poc_command"`
	ResponseHeaders string `json:"response_headers"`
	ResponsePreview string `json:"response_preview"`
	StatusCode      int    `json:"response_status_code"`
	ContentType     string `json:"response_content_type"`
	ContentLength   int64  `json:"response_content_length"`
	ResponseBytes   int    `json:"response_bytes"`
	Title           string `json:"response_title"`
	ServerInfo      string `json:"response_server_info"`
	RedirectURL     string `json:"response_redirect_url"`
	HTMLFilename    string `json:"response_html_filename"`
}

type ScanResult struct {
	URL         string    `json:"url"`
	BypassModes string    `json:"bypass_modes"`
	ResultsPath string    `json:"results_path"`
	Results     []*Result `json:"results"`
}

type JSONData struct {
	Scans []ScanResult `json:"scans"`
}

// ModesConfig -- all bypass modes and their status
type ModesConfig struct {
	Name        string
	Enabled     bool
	Description string
}

// AvailableModes defines all bypass modes and their default status
var AvailableModes = map[string]ModesConfig{
	"all": {
		Name:        "all",
		Enabled:     true,
		Description: "Run all enabled bypass modes",
	},
	"mid_paths": {
		Name:        "mid_paths",
		Enabled:     true,
		Description: "Test middle path bypasses",
	},
	"end_paths": {
		Name:        "end_paths",
		Enabled:     true,
		Description: "Test end path bypasses",
	},
	"http_host": {
		Name:        "http_host",
		Enabled:     true,
		Description: "Test HTTP Host header bypasses",
	},
	"http_methods": {
		Name:        "http_methods",
		Enabled:     false,
		Description: "Test different HTTP methods",
	},
	"http_versions": {
		Name:        "http_versions",
		Enabled:     false,
		Description: "Test different HTTP versions",
	},
	"case_substitution": {
		Name:        "case_substitution",
		Enabled:     true,
		Description: "Test case manipulation bypasses",
	},
	"char_encode": {
		Name:        "char_encode",
		Enabled:     true,
		Description: "Test character encoding bypasses",
	},
	"http_headers_method": {
		Name:        "http_headers_method",
		Enabled:     false,
		Description: "Test HTTP method header bypasses",
	},
	"http_headers_scheme": {
		Name:        "http_headers_scheme",
		Enabled:     true,
		Description: "Test HTTP scheme header bypasses",
	},
	"http_headers_ip": {
		Name:        "http_headers_ip",
		Enabled:     true,
		Description: "Test IP-based header bypasses",
	},
	"http_headers_port": {
		Name:        "http_headers_port",
		Enabled:     true,
		Description: "Test port-based header bypasses",
	},
	"http_headers_url": {
		Name:        "http_headers_url",
		Enabled:     true,
		Description: "Test URL-based header bypasses",
	},
	"user_agent": {
		Name:        "user_agent",
		Enabled:     false, // waste of time
		Description: "Test User-Agent based bypasses",
	},
}

// HttpxResultsCache is a cache for the probing phase
type HttpxResultsCache struct {
	sync.RWMutex
	hostResults gcache.Cache[string, *HttpxResult]
}

func NewHttpxResultsCache() *HttpxResultsCache {
	return &HttpxResultsCache{
		hostResults: gcache.New[string, *HttpxResult](1000).
			LRU().
			Build(),
	}
}

// Helper function to check if the scheme already exists
func validateScheme(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (c *HttpxResultsCache) UpdateHost(r runner.Result) error {
	c.Lock()
	defer c.Unlock()

	host := r.Host
	result, err := c.hostResults.Get(host)
	if err != nil {
		// Create new result if host doesn't exist
		result = &HttpxResult{
			Host:    host,
			Port:    r.Port,
			Schemes: []string{r.Scheme},
			IPv4:    r.A,
			IPv6:    r.AAAA,
			CNAMEs:  r.CNAMEs,
		}
	} else {
		// Update existing result
		// Add new scheme if not present
		if !validateScheme(result.Schemes, r.Scheme) {
			result.Schemes = append(result.Schemes, r.Scheme)
		}

		// Update IPs - merge without duplicates
		result.IPv4 = mergeUnique(result.IPv4, r.A)
		result.IPv6 = mergeUnique(result.IPv6, r.AAAA)
		result.CNAMEs = mergeUnique(result.CNAMEs, r.CNAMEs)

		// Update port if different
		if r.Port != "" && r.Port != result.Port {
			result.Port = r.Port
		}
	}

	return c.hostResults.Set(host, result)
}

// Helper function to merge strings without duplicates
func mergeUnique(existing, new []string) []string {
	seen := make(map[string]bool)
	merged := make([]string, 0)

	// Add existing items
	for _, item := range existing {
		if !seen[item] {
			seen[item] = true
			merged = append(merged, item)
		}
	}

	// Add new items
	for _, item := range new {
		if !seen[item] {
			seen[item] = true
			merged = append(merged, item)
		}
	}

	return merged
}

func (c *HttpxResultsCache) Store(host string, result *HttpxResult) error {
	c.Lock()
	defer c.Unlock()
	return c.hostResults.Set(host, result)
}

func (c *HttpxResultsCache) Get(host string) (*HttpxResult, bool) {
	c.RLock()
	defer c.RUnlock()
	result, err := c.hostResults.Get(host)
	return result, err == nil
}

func (c *HttpxResultsCache) Delete(host string) {
	c.Lock()
	defer c.Unlock()
	c.hostResults.Remove(host)
}

func (c *HttpxResultsCache) Purge() {
	c.Lock()
	defer c.Unlock()
	c.hostResults.Purge()
}

// Initialize global cache
var globalHttpxResults = NewHttpxResultsCache()

// Other Constants //
const (
	defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
	defaultTimeout   = 30 * time.Second
	maxIdleConns     = 100
	jobBufferSize    = 1000
)
