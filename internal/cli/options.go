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

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
)

// Options represents command-line options
type CliOptions struct {
	// Input options
	URL                 string
	URLsFile            string
	SubstituteHostsFile string

	// Scan configuration
	Module                   string
	MatchStatusCodesStr      string
	MatchStatusCodes         []int
	Threads                  int
	Timeout                  int
	Delay                    int
	MaxRetries               int
	RetryDelay               int // in milliseconds
	MaxConsecutiveFailedReqs int
	ResponseBodyPreviewSize  int // in bytes, we don't need too much, Response Headers and a small body preview is enough

	// Output options
	OutDir  string
	Verbose bool
	Debug   bool

	// Network options
	Proxy           string
	ParsedProxy     *url.URL
	EnableHTTP2     bool // not implemented yet
	FollowRedirects bool // not implemented yet

	// Spoofing options
	SpoofIP     string
	SpoofHeader string

	// StreamResponseBody
	DisableStreamResponseBody bool

	// ResendRequest
	ResendRequest string

	//UpdatePayloads
	UpdatePayloads bool

	// Enable profiler
	Profile bool
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

func (o *CliOptions) printUsage(flagName ...string) {
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
func (o *CliOptions) setDefaults() {
	// Core defaults
	o.UpdatePayloads = false

	if o.Module == "" {
		o.Module = "all"
	}
	if o.Threads == 0 {
		o.Threads = 15
	}
	if o.Timeout == 0 {
		o.Timeout = 20000
	}
	if o.Delay <= 0 {
		o.Delay = 0
	}

	if o.RetryDelay == 0 {
		o.RetryDelay = 500
	}

	// Status codes default - accept all codes
	if o.MatchStatusCodesStr == "" {
		o.MatchStatusCodes = nil // nil means match all status codes
	}

	// Output directory default
	if o.OutDir == "" {
		o.OutDir = filepath.Join(os.TempDir(), fmt.Sprintf("go-bypass-403-%x", time.Now().UnixNano()))
	}

	// Max response body size default
	if o.ResponseBodyPreviewSize < 0 {
		o.ResponseBodyPreviewSize = 1024
	}
}

// validate performs all validation checks
func (o *CliOptions) validate() error {
	if o.UpdatePayloads {
		return payload.UpdatePayloads()
	}

	if o.ResendRequest != "" {
		data, err := payload.DecodeDebugToken(o.ResendRequest)
		if err != nil {
			return fmt.Errorf("invalid debug token: %v", err)
		}
		// Print the decoded information
		fmt.Println("=== Debug Token Information ===")
		fmt.Printf("Full URL: %s\n", data.FullURL)
		fmt.Printf("Bypass Module: %s\n", data.BypassModule)
		fmt.Println("Headers:")
		for _, h := range data.Headers {
			fmt.Printf("  %s: %s\n", h.Header, h.Value)
		}
	}

	// Validate input parameters
	if err := o.validateInputURLs(); err != nil && o.ResendRequest == "" {
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
func (o *CliOptions) validateInputURLs() error {
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
func (o *CliOptions) processStatusCodes() error {
	if o.MatchStatusCodesStr == "" {
		return nil // Default was set in setDefaults (nil = match all)
	}

	// Handle "all" or "*" cases
	if o.MatchStatusCodesStr == "all" || o.MatchStatusCodesStr == "*" {
		o.MatchStatusCodes = nil // nil means match all status codes
		return nil
	}

	var codes []int
	parts := strings.Split(o.MatchStatusCodesStr, ",")
	for _, p := range strings.Fields(strings.Join(parts, " ")) {
		code, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			continue
		}
		// Accept any positive integer as a status code
		if code > 0 {
			codes = append(codes, code)
		}
	}

	if len(codes) > 0 {
		o.MatchStatusCodes = codes
	}
	return nil
}

// validateModule checks if the specified module is valid
func (o *CliOptions) validateModule() error {
	if o.Module == "" {
		return fmt.Errorf("bypass module cannot be empty")
	}

	// Split and validate each module
	modules := strings.Split(o.Module, ",")
	for _, m := range modules {
		m = strings.TrimSpace(m)
		if m == "all" {
			return nil // basically "all"
		}
		if enabled, exists := AvailableModules[m]; !exists || !enabled {
			return fmt.Errorf("invalid module: %s", m)
		}
	}

	return nil
}

// setupOutputDir creates the output directory and initializes findings.json
func (o *CliOptions) setupOutputDir() error {
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

func (o *CliOptions) processProxy() error {
	if o.Proxy == "" {
		return nil
	}

	parsedProxy, err := url.Parse(o.Proxy)
	if err != nil {
		o.printUsage("proxy")
		fmt.Println()
		return fmt.Errorf("invalid proxy URL: %v", err)
	}

	o.ParsedProxy = parsedProxy
	return nil
}
