// config.go
package main

import (
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/rawhttp"
)

var (
	isVerbose bool
	config    Config
)

const (
	VERSION = "0.2.3"
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
	ForceHTTP2          bool
	SpoofIP             string
	SpoofHeader         string
	Delay               int
	FollowRedirects     bool
}

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
		Enabled:     false,
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

// Needed by ProgressCounter
type ProgressCounter struct {
	total   int
	current int
	mode    string
	mu      sync.Mutex
}

// Other Constants
const (
	defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
	defaultTimeout   = 30 * time.Second
	maxIdleConns     = 100
	jobBufferSize    = 1000
)

// Other Vars and stuff
// global rawhttpclient
var (
	globalRawClient *rawhttp.Client
)

// initRawHTTPClient -- initializes the rawhttp client
func initRawHTTPClient() {
	// Set fastdialer options from scratch
	fastdialerOpts := fastdialer.Options{
		BaseResolvers: []string{
			"1.1.1.1:53",
			"1.0.0.1:53",
			"9.9.9.10:53",
			"8.8.4.4:53",
		},
		MaxRetries:    5,
		HostsFile:     true,
		ResolversFile: true,
		CacheType:     fastdialer.Disk,
		DiskDbType:    fastdialer.LevelDB,

		// Timeouts
		DialerTimeout:   10 * time.Second,
		DialerKeepAlive: 10 * time.Second,

		// Cache settings
		CacheMemoryMaxItems: 200,
		WithDialerHistory:   true,
		WithCleanup:         true,

		// TLS settings
		WithZTLS:            true,
		DisableZtlsFallback: false,

		// Fallback settings
		EnableFallback: true,

		// Error handling
		MaxTemporaryErrors:              15,
		MaxTemporaryToPermanentDuration: 2 * time.Minute, // Our custom value (default was 1 minute)
	}

	// Use fastdialer
	dialer, err := fastdialer.NewDialer(fastdialerOpts)
	if err != nil {
		LogError("[initRawHTTPClient] Failed to create dialer: %v\n", err)
		return
	}

	options := &rawhttp.Options{
		Timeout:                time.Duration(config.Timeout) * time.Second,
		FollowRedirects:        config.FollowRedirects,
		MaxRedirects:           map[bool]int{false: 0, true: 10}[config.FollowRedirects],
		AutomaticHostHeader:    false,
		AutomaticContentLength: true,
		ForceReadAllBody:       true,
		FastDialer:             dialer,
	}

	if config.Proxy != "" {
		if !strings.HasPrefix(config.Proxy, "http://") && !strings.HasPrefix(config.Proxy, "https://") {
			config.Proxy = "http://" + config.Proxy
		}
		options.Proxy = config.Proxy
		options.ProxyDialTimeout = 10 * time.Second
	}

	globalRawClient = rawhttp.NewClient(options)
}
