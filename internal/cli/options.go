package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Options represents command-line options
type Options struct {
	// Input options
	URL                 string
	URLsFile            string
	SubstituteHostsFile string

	// Scan configuration
	Module                  string
	MatchStatusCodesStr     string
	MatchStatusCodes        []int
	Threads                 int
	Timeout                 int
	Delay                   int
	ResponseBodyPreviewSize int // in bytes, we don't need too much, Response Headers and a small body preview is enough

	// Output options
	OutDir        string
	Verbose       bool
	Debug         bool
	TraceRequests bool

	// Network options
	Proxy           string
	ParsedProxy     *url.URL
	EnableHTTP2     bool
	FollowRedirects bool

	// Spoofing options
	SpoofIP     string
	SpoofHeader string
}

// ModesConfig -- all bypass modes and their status
type ModulesConfig struct {
	Name        string
	Enabled     bool
	Description string
}

// AvailableModes defines all bypass modes and their status, true if enabled, false if disabled
var AvailableModules = map[string]bool{
	"all":                 true,
	"mid_paths":           true,
	"end_paths":           true,
	"case_substitution":   true,
	"char_encode":         true,
	"http_headers_scheme": true,
	"http_headers_ip":     true,
	"http_headers_port":   true,
	"http_headers_url":    true,
	"http_host":           true,
}

// Add this method to your Options struct
// printUsage prints either full usage or specific flag usage
func (o *Options) printUsage(flagName ...string) {
	if len(flagName) == 0 {
		flag.Usage()
		return
	}

	// Print header only for specific flag usage
	fmt.Fprintf(os.Stderr, "Go-Bypass-403\n\n")

	// Search for the specific flag in our flags slice
	for _, f := range flags {
		names := strings.Split(f.name, ",")
		for _, name := range names {
			if name == flagName[0] {
				if len(names) > 1 {
					fmt.Fprintf(os.Stderr, "  -%s, -%s\n", names[0], names[1])
				} else {
					fmt.Fprintf(os.Stderr, "  -%s\n", names[0])
				}

				if f.defVal != nil {
					fmt.Fprintf(os.Stderr, "        %s (Default: %v)\n", f.usage, f.defVal)
				} else {
					fmt.Fprintf(os.Stderr, "        %s\n", f.usage)
				}
				return
			}
		}
	}
}

// setDefaults sets default values for options
func (o *Options) setDefaults() {
	// Core defaults
	if o.Module == "" {
		o.Module = "all"
	}
	if o.Threads == 0 {
		o.Threads = 15
	}
	if o.Timeout == 0 {
		o.Timeout = 20
	}
	if o.Delay <= 0 {
		o.Delay = 150
	}

	o.TraceRequests = false

	// Status codes default
	if o.MatchStatusCodesStr == "" {
		o.MatchStatusCodes = []int{200}
	}

	// Output directory default
	if o.OutDir == "" {
		o.OutDir = filepath.Join(os.TempDir(), fmt.Sprintf("go-bypass-403-%x", time.Now().UnixNano()))
	}

	// Max response body size default
	if o.ResponseBodyPreviewSize < 0 {
		o.ResponseBodyPreviewSize = 512
	}
}

// validate performs all validation checks
func (o *Options) validate() error {
	// Validate input parameters
	if err := o.validateInputURLs(); err != nil {
		return err
	}

	// Process and validate status codes
	if err := o.processStatusCodes(); err != nil {
		return err
	}

	// Validate module
	if err := o.validateModule(); err != nil {
		return err
	}

	// Setup output directory
	if err := o.setupOutputDir(); err != nil {
		return err
	}

	// Process proxy if provided
	if err := o.processProxy(); err != nil {
		return err
	}

	return nil
}

// validateInputs checks URL and file inputs
func (o *Options) validateInputURLs() error {
	if o.URL == "" && o.URLsFile == "" {
		return fmt.Errorf("either URL (-u) or URLs file (-l) is required")
	}

	if o.URL != "" && o.URLsFile != "" {
		return fmt.Errorf("cannot use both URL (-u) and URLs file (-l)")
	}

	if o.SubstituteHostsFile != "" {
		if o.URL == "" {
			return fmt.Errorf("target URL (-u) is required when using substitute hosts file")
		}
		if o.URLsFile != "" {
			return fmt.Errorf("cannot use both URLs file (-l) and substitute hosts file")
		}
	}

	return nil
}

// processStatusCodes processes the status codes string
func (o *Options) processStatusCodes() error {
	if o.MatchStatusCodesStr == "" {
		return nil // Default was set in setDefaults
	}

	var codes []int
	parts := strings.Split(o.MatchStatusCodesStr, ",")
	for _, p := range strings.Fields(strings.Join(parts, " ")) {
		code, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			continue
		}
		if code >= 100 && code < 600 {
			codes = append(codes, code)
		}
	}

	if len(codes) > 0 {
		o.MatchStatusCodes = codes
	}
	return nil
}

// validateModule checks if the specified module is valid
func (o *Options) validateModule() error {
	if !AvailableModules[o.Module] {
		o.printUsage("module")
		fmt.Println()
		return fmt.Errorf("invalid module: %s", o.Module)
	}
	return nil
}

// setupOutputDir creates the output directory and initializes findings.json
func (o *Options) setupOutputDir() error {
	if err := os.MkdirAll(o.OutDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Initialize findings.json file
	outputFile := filepath.Join(o.OutDir, "findings.json")
	initialJSON := struct {
		Scans []interface{} `json:"scans"`
	}{
		Scans: make([]interface{}, 0),
	}

	jsonData, err := json.MarshalIndent(initialJSON, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to create initial JSON structure: %v", err)
	}

	if err := os.WriteFile(outputFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to initialize findings.json: %v", err)
	}

	return nil
}

func (o *Options) processProxy() error {
	if o.Proxy == "" {
		return nil
	}

	parsedProxy, err := url.Parse(o.Proxy)
	if err != nil {
		o.printUsage("proxy")
		fmt.Println()
		return fmt.Errorf("\ninvalid proxy URL: %v\n", err)
	}

	o.ParsedProxy = parsedProxy
	return nil
}
