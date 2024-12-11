package config

import (
	"time"
)

const (
	VERSION = "0.3.1"
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

// Other Constants //
const (
	defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
	defaultTimeout   = 30 * time.Second
	maxIdleConns     = 100
	jobBufferSize    = 1000
)
