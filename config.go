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
	VERSION = "0.2.0"
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

// Constants
//
// Bypass Modes
const (
	ModeAll              = "all"
	ModeMidPaths         = "mid_paths" // done
	ModeEndPaths         = "end_paths" // done
	ModeHTTPHost         = "http_host"
	ModeHTTPMethods      = "http_methods"
	ModeHTTPVersions     = "http_versions"
	ModeCaseSubstitution = "case_substitution" //done
	ModeCharEncode       = "char_encode"       //done
	ModeHeadersMethod    = "http_headers_method"
	ModeHeadersScheme    = "http_headers_scheme" // done
	ModeHeadersIP        = "http_headers_ip"     // done
	ModeHeadersPort      = "http_headers_port"   // done
	ModeHeadersURL       = "http_headers_url"    // done
	ModeUserAgent        = "user_agent"          // waste of time
)

// Other Constants
const (
	defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
	defaultTimeout   = 30 * time.Second
	maxIdleConns     = 100
)
