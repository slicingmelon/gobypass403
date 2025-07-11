/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package cli

import (
	"bytes"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
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
	MatchContentType         string   // New field for multiple types
	MatchContentTypeBytes    [][]byte // Multiple byte slices for efficient matching
	MinContentLengthStr      string   // Minimum Content-Length to match (as string)
	MaxContentLengthStr      string   // Maximum Content-Length to match (as string)
	MinContentLength         int      // Parsed min content length value
	MaxContentLength         int      // Parsed max content length value
	ConcurrentRequests       int
	Timeout                  int
	Delay                    int
	MaxRetries               int
	RetryDelay               int // in milliseconds
	RequestDelay             int // in milliseconds
	MaxConsecutiveFailedReqs int
	AutoThrottle             bool
	ResponseBodyPreviewSize  int // in bytes, we don't need too much, Response Headers and a small body preview is enough

	// Custom HTTP Headers
	CustomHTTPHeaders []string // Stores custom headers in "Name: Value" format

	// Output options
	OutDir        string
	ResultsDBFile string
	Verbose       bool
	Debug         bool

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
	DisableProgressBar        bool

	// ResendRequest
	ResendRequest string
	ResendNum     int

	//UpdatePayloads
	UpdatePayloads bool

	// Enable profiler
	Profile bool
}

// AvailableModes defines all bypass modes and their status, true if enabled, false if disabled
var AvailableModules = map[string]bool{
	"dumb_check":                 true,
	"path_prefix":                true,
	"mid_paths":                  true,
	"end_paths":                  true,
	"http_methods":               true,
	"case_substitution":          true,
	"char_encode":                true,
	"nginx_bypasses":             true,
	"haproxy_bypasses":           true,
	"headers_scheme":             true,
	"headers_ip":                 true,
	"headers_port":               true,
	"headers_url":                true,
	"headers_host":               true,
	"unicode_path_normalization": true,
}

func (o *CliOptions) printUsage(flagName ...string) {
	if len(flagName) == 0 {
		flag.Usage()
		return
	}

	// Print header only for specific flag usage
	fmt.Fprintf(os.Stderr, "GoByPASS403\n\n")

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
	//o.UpdatePayloads = false

	if o.Module == "" {
		o.Module = "all"
	}
	if o.ConcurrentRequests == 0 {
		o.ConcurrentRequests = 15
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

	// enable auto throttle by default
	if !o.AutoThrottle {
		o.AutoThrottle = true
	}

	// Output directory default
	if o.OutDir == "" {
		o.OutDir = filepath.Join(os.TempDir(), "gobypass403_tmp", fmt.Sprintf("gobypass403_%x", time.Now().UnixNano()))
	}

	if o.ResultsDBFile == "" {
		o.ResultsDBFile = filepath.Join(o.OutDir, "results.db")
	}

	// Max response body size default
	if o.ResponseBodyPreviewSize < 0 {
		o.ResponseBodyPreviewSize = 1024
	}
}

// validate performs all validation checks
func (o *CliOptions) validate() error {
	// Check for update payloads first
	if o.UpdatePayloads {
		if err := payload.UpdatePayloads(); err != nil {
			return fmt.Errorf("failed to update payloads: %v", err)
		}
		GB403Logger.Success().Msgf("Payloads updated successfully")
		os.Exit(0)
	}

	if o.ResendRequest != "" {
		data, err := payload.DecodePayloadToken(o.ResendRequest)
		if err != nil {
			return fmt.Errorf("invalid debug token: %v", err)
		}
		// Print the decoded information
		targetURL := fmt.Sprintf("%s://%s%s", data.Scheme, data.Host, data.RawURI)

		GB403Logger.PrintYellowLn("=== Debug Token Information ===")
		GB403Logger.PrintYellow("Full URL: %s\n", targetURL)
		GB403Logger.PrintYellow("Scheme: %s\n", data.Scheme)
		GB403Logger.PrintYellow("Method: %s\n", data.Method)
		GB403Logger.PrintYellow("Host: %s\n", data.Host)
		GB403Logger.PrintYellow("RawURI: %s\n", data.RawURI)
		GB403Logger.PrintYellow("Headers:\n")
		for _, h := range data.Headers {
			GB403Logger.PrintYellow("  %s: %s\n", h.Header, h.Value)
		}
		GB403Logger.PrintYellow("Bypass Module: %s\n\n", data.BypassModule)
	}

	// Validate input parameters
	if err := o.validateInputURLs(); err != nil && o.ResendRequest == "" {
		return err
	}

	// Validate custom HTTP headers
	if err := o.validateCustomHeaders(); err != nil {
		return err
	}

	// Process and validate status codes
	if err := o.processStatusCodes(); err != nil {
		return err
	}

	// Validate content length options
	if o.MinContentLengthStr != "" {
		minCL, err := strconv.Atoi(o.MinContentLengthStr)
		if err != nil {
			return fmt.Errorf("invalid integer value for -min-cl: %w", err)
		}
		o.MinContentLength = minCL
	}

	if o.MaxContentLengthStr != "" {
		maxCL, err := strconv.Atoi(o.MaxContentLengthStr)
		if err != nil {
			return fmt.Errorf("invalid integer value for -max-cl: %w", err)
		}
		o.MaxContentLength = maxCL
	}

	// Check min > max only if both are set
	if o.MinContentLength > 0 && o.MaxContentLength > 0 && o.MinContentLength > o.MaxContentLength {
		return fmt.Errorf("minimum content length (%d) cannot be greater than maximum content length (%d)",
			o.MinContentLength, o.MaxContentLength)
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

	if o.MatchContentType != "" {
		// Split by comma, allowing for spaces
		types := strings.Split(o.MatchContentType, ",")
		for _, t := range types {
			t = strings.TrimSpace(t)
			if t != "" {
				o.MatchContentTypeBytes = append(o.MatchContentTypeBytes, bytes.ToLower([]byte(t)))
			}
		}
	}

	// Check if payloads are outdated
	if !o.UpdatePayloads && o.ResendRequest == "" {
		consistent, err := payload.CheckOutdatedPayloads()

		if err != nil {
			// Log error but continue scan, as it might be a permission issue
			GB403Logger.Error().Msgf("Error checking for outdated payloads: %v", err)
		} else if !consistent {
			GB403Logger.Warning().Msgf("Local payloads may be outdated or modified. Run with -update-payloads to ensure you have the latest versions.\n\n")
		}
	}

	return nil
}

// validateInputs checks URL and file inputs
func (o *CliOptions) validateInputURLs() error {
	if o.UpdatePayloads {
		return nil
	}

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

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Check for wildcard pattern (e.g., 2xx, 3xx, etc.)
		if len(part) == 3 && strings.HasSuffix(part, "xx") {
			firstDigit, err := strconv.Atoi(part[0:1])
			if err == nil && firstDigit >= 1 && firstDigit <= 5 {
				// Add all codes in the range (e.g., 200-299 for 2xx)
				for i := 0; i < 100; i++ {
					codes = append(codes, firstDigit*100+i)
				}
				continue
			}
		}

		// Standard numeric code handling
		code, err := strconv.Atoi(part)
		if err != nil {
			// Silently skip invalid codes
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
		o.printUsage("module")
		return fmt.Errorf("bypass module cannot be empty")
	}

	// Always process as comma-separated list
	modules := strings.Split(o.Module, ",")
	finalModules := make([]string, 0, len(modules))

	// Check for "all" first
	for _, m := range modules {
		if strings.TrimSpace(m) == "all" {
			// Expand to all available modules except "dumb_check"
			for moduleName := range AvailableModules {
				if moduleName != "dumb_check" {
					finalModules = append(finalModules, moduleName)
				}
			}
			break
		}
	}

	// If not "all", validate individual modules
	if len(finalModules) == 0 {
		for _, m := range modules {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			if enabled, exists := AvailableModules[m]; !exists || !enabled {
				return fmt.Errorf("invalid module: %s", m)
			}
			finalModules = append(finalModules, m)
		}
	}

	// Always prepend dumb_check unless explicitly excluded
	if !slices.Contains(finalModules, "dumb_check") {
		finalModules = append([]string{"dumb_check"}, finalModules...)
	}

	// Join back to comma-separated string
	o.Module = strings.Join(finalModules, ",")
	return nil
}

// setupOutputDir creates the output directory
func (o *CliOptions) setupOutputDir() error {
	if err := os.MkdirAll(o.OutDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
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

// validateCustomHeaders checks and pre-processes custom headers
func (o *CliOptions) validateCustomHeaders() error {
	if len(o.CustomHTTPHeaders) == 0 {
		return nil
	}

	for i, header := range o.CustomHTTPHeaders {
		colonIdx := strings.Index(header, ":")
		if colonIdx == -1 {
			return fmt.Errorf("invalid header format for header #%d '%s': must be in 'Header: Value' format", i+1, header)
		}

		headerName := strings.TrimSpace(header[:colonIdx])
		if headerName == "" {
			return fmt.Errorf("empty header name for header #%d", i+1)
		}
	}

	return nil
}
