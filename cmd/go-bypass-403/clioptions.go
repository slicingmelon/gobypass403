package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/slicingmelon/go-bypass-403/internal/utils"
)

// Options represents command-line options
type Options struct {
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
	LogDebugToFile      bool
	ForceHTTP2          bool
	SpoofIP             string
	SpoofHeader         string
	Delay               int
	FollowRedirects     bool
	TraceRequests       bool
}

type multiFlag struct {
	name   string
	usage  string
	value  interface{}
	defVal interface{}
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

// ParseOptions parses and validates command line flags
func ParseCliOptions() (*Options, error) {
	opts := &Options{}

	flags := []multiFlag{
		{name: "u,url", usage: "Target URL (example: https://cms.facebook.com/login)", value: &opts.URL},
		{name: "l,urls-file", usage: "File containing list of target URLs (one per line)", value: &opts.URLsFile},
		{name: "shf,substitute-hosts-file", usage: "File containing hosts to substitute target URL's hostname", value: &opts.SubstituteHostsFile},
		{name: "m,mode", usage: "Bypass mode (all, mid_paths, end_paths, etc)", value: &opts.Mode, defVal: "all"},
		{name: "o,outdir", usage: "Output directory", value: &opts.OutDir},
		{name: "t,threads", usage: "Number of concurrent threads", value: &opts.Threads, defVal: 15},
		{name: "T,timeout", usage: "Timeout in seconds", value: &opts.Timeout, defVal: 15},
		{name: "delay", usage: "Delay between requests in milliseconds", value: &opts.Delay, defVal: 150},
		{name: "v,verbose", usage: "Verbose output", value: &opts.Verbose},
		{name: "d,debug", usage: "Debug mode with request canaries", value: &opts.Debug},
		{name: "trace", usage: "Trace HTTP requests", value: &opts.TraceRequests},
		{name: "mc,match-status-code", usage: "Match HTTP status codes (example: 200,301,500)", value: &opts.MatchStatusCodesStr},
		{name: "http2", usage: "Force attempt requests on HTTP2", value: &opts.ForceHTTP2},
		{name: "x,proxy", usage: "Proxy URL (format: http://proxy:port)", value: &opts.Proxy},
		{name: "spoof-header", usage: "Headers used to spoof IPs", value: &opts.SpoofHeader},
		{name: "spoof-ip", usage: "IP addresses to spoof", value: &opts.SpoofIP},
		{name: "follow-redirects", usage: "Follow redirects", value: &opts.FollowRedirects},
	}

	// Register all flags
	for _, f := range flags {
		for _, name := range strings.Split(f.name, ",") {
			name = strings.TrimSpace(name)
			switch v := f.value.(type) {
			case *string:
				if def, ok := f.defVal.(string); ok {
					flag.StringVar(v, name, def, f.usage)
				} else {
					flag.StringVar(v, name, "", f.usage)
				}
			case *int:
				if def, ok := f.defVal.(int); ok {
					flag.IntVar(v, name, def, f.usage)
				} else {
					flag.IntVar(v, name, 0, f.usage)
				}
			case *bool:
				if def, ok := f.defVal.(bool); ok {
					flag.BoolVar(v, name, def, f.usage)
				} else {
					flag.BoolVar(v, name, false, f.usage)
				}
			}
		}
	}

	flag.Parse()

	// Process and validate options
	if err := opts.processAndValidate(); err != nil {
		return nil, err
	}

	return opts, nil
}

// processAndValidate processes and validates all options after parsing
func (o *Options) processAndValidate() error {
	// Set defaults and validate
	if o.Delay <= 0 {
		o.Delay = 150
	}

	// Process match status codes
	if o.MatchStatusCodesStr == "" {
		o.MatchStatusCodes = []int{200}
	} else {
		if err := o.parseMatchStatusCodes(); err != nil {
			return err
		}
	}

	// Validate bypass mode
	if err := validateMode(o.Mode); err != nil {
		return err
	}

	// Setup output directory
	if o.OutDir == "" {
		o.OutDir = filepath.Join(os.TempDir(), fmt.Sprintf("go-bypass-403-%x", time.Now().UnixNano()))
	}

	// Parse proxy if provided
	if o.Proxy != "" {
		parsedProxy, err := url.Parse(o.Proxy)
		if err != nil {
			return fmt.Errorf("failed to parse proxy URL: %v", err)
		}
		o.ParsedProxy = parsedProxy
	}

	return nil
}

// parseMatchStatusCodes parses the status codes string into integers
func (o *Options) parseMatchStatusCodes() error {
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

// get bypass modes quickly
func GetAvailableModes() map[string]bool {
	modes := make(map[string]bool)
	for key, mode := range AvailableModes {
		if mode.Enabled {
			modes[key] = true
		}
	}
	return modes
}

// validate bypass mode
func ValidateBypassModule(mode string) error {
	availableModes := getBypassModules()
	modes := strings.Split(mode, ",")

	for _, m := range modes {
		m = strings.TrimSpace(m)
		if !availableModes[m] {
			// Create a sorted list of available modes
			var modeList []string
			for mode := range availableModes {
				modeList = append(modeList, mode)
			}
			sort.Strings(modeList)

			LogOrange("\nInvalid bypass mode: %s\nAvailable modes: %s\n",
				m, strings.Join(modeList, ", "))
			return fmt.Errorf("")
		}
	}
	return nil
}
