// config.go
package main

import (
	"net/url"
	"time"
)

var (
	isVerbose bool
	config    Config
)

const (
	VERSION = "0.2.6"
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

// Other Constants
const (
	defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
	defaultTimeout   = 30 * time.Second
	maxIdleConns     = 100
	jobBufferSize    = 1000
)
