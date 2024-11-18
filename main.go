// main.go
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/slicingmelon/go-rawurlparser"
)

type multiFlag struct {
	name   string
	usage  string
	value  interface{}
	defVal interface{}
}

// get bypass modes quickly
func getAvailableModes() map[string]bool {
	modes := make(map[string]bool)
	for key, mode := range AvailableModes {
		if mode.Enabled {
			modes[key] = true
		}
	}
	return modes
}

// validate bypass mode
func validateMode(mode string) error {
	availableModes := getAvailableModes()
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

// Main Function //
func main() {
	flags := []multiFlag{
		{name: "u,url", usage: "Target URL (example: https://cms.facebook.com/login)", value: &config.URL},
		{name: "l,urls-file", usage: "File containing list of target URLs (one per line)", value: &config.URLsFile},
		{name: "shf,substitute-hosts-file", usage: "File containing a list of hosts to substitute target URL's hostname (mostly used in CDN bypasses by providing a list of CDNs)", value: &config.SubstituteHostsFile},
		{name: "m,mode", usage: "Bypass mode (all, mid_paths, end_paths, case_substitution, char_encode, http_headers_scheme, http_headers_ip, http_headers_port, http_headers_url)", value: &config.Mode, defVal: "all"},
		{name: "o,outdir", usage: "Output directory", value: &config.OutDir},
		{name: "t,threads", usage: "Number of concurrent threads)", value: &config.Threads, defVal: 20},
		{name: "T,timeout", usage: "Timeout in seconds", value: &config.Timeout, defVal: 15},
		{name: "delay", usage: "Delay between requests in milliseconds (Default: 150ms)", value: &config.Delay, defVal: 150},
		{name: "v,verbose", usage: "Verbose output", value: &config.Verbose, defVal: false},
		{name: "d,debug", usage: "Debug mode with request canaries", value: &config.Debug, defVal: false},
		{name: "mc,match-status-code", usage: "Only save results matching these HTTP status codes (example: -mc 200,301,500). Default: 200", value: &config.MatchStatusCodesStr},
		{name: "http2", usage: "Force attempt requests on HTTP2", value: &config.ForceHTTP2, defVal: false},
		{name: "x,proxy", usage: "Proxy URL (format: http://proxy:port)", value: &config.Proxy},
		{name: "spoof-header", usage: "Add more headers used to spoof IPs (example: X-SecretIP-Header,X-GO-IP)", value: &config.SpoofHeader},
		{name: "spoof-ip", usage: "Add more spoof IPs (example: 10.10.20.20,172.16.30.10)", value: &config.SpoofIP},
	}

	// Usage helper
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Go-Bypass-403: v%s\n", VERSION)
		for _, f := range flags {
			names := strings.Split(f.name, ",")
			if len(names) > 1 {
				fmt.Fprintf(os.Stderr, "  -%s, -%s\n", names[0], names[1])
			} else {
				fmt.Fprintf(os.Stderr, "  -%s\n", names[0])
			}

			// Add default value if it exists
			if f.defVal != nil {
				fmt.Fprintf(os.Stderr, "        %s (Default: %v)\n", f.usage, f.defVal)
			} else {
				fmt.Fprintf(os.Stderr, "        %s\n", f.usage)
			}
		}
	}

	// register flags
	for _, f := range flags {
		names := strings.Split(f.name, ",")
		for _, name := range names {
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

	// Parse flags
	flag.Parse()

	// Set up a small delay between requests
	if config.Delay <= 0 {
		config.Delay = 150 // Default to 150s if set invalid
	}

	if config.MatchStatusCodesStr == "" {
		config.MatchStatusCodes = []int{200}
	} else {
		parts := strings.Split(config.MatchStatusCodesStr, ",")
		for _, p := range strings.Fields(strings.Join(parts, " ")) {
			if code, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
				if code >= 100 && code < 600 {
					config.MatchStatusCodes = append(config.MatchStatusCodes, code)
				}
			}
		}
		if len(config.MatchStatusCodes) == 0 {
			config.MatchStatusCodes = []int{200}
		}
	}

	// Set verbose mode for logger
	SetVerbose(config.Verbose)

	// Validate bypass mode
	if err := validateMode(config.Mode); err != nil {
		//fmt.Println("Error:", err)
		//flag.Usage()
		os.Exit(1)
	}

	// Validate input URL(s)
	if config.URL == "" && config.URLsFile == "" {
		fmt.Println("Error: Either Target URL (-u) or URLs file (-l) is required")
		flag.Usage()
		os.Exit(1)
	}

	if config.SubstituteHostsFile != "" {
		if config.URL == "" {
			fmt.Println("Error: Target URL (-u) is required when using substitute hosts file (-substitute-hosts-file/-shf)")
			flag.Usage()
			os.Exit(1)
		}
		if config.URLsFile != "" {
			fmt.Println("Error: Cannot use both URLs file (-l) and substitute hosts file (-substitute-hosts-file/-shf)")
			flag.Usage()
			os.Exit(1)
		}
	}

	// list of urls to be scanned
	var urls []string

	// First handle the direct URL if provided
	if config.URL != "" {
		// Basic validation first
		if err := validateURL(config.URL); err != nil {
			LogError("Invalid target URL: %v\n", err)
			os.Exit(1)
		}

		parsedURL := rawurlparser.RawURLParse(config.URL)
		if parsedURL == nil {
			LogError("Failed to parse target URL\n")
			os.Exit(1)
		}

		// base url
		baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

		// Combine path and query
		originalPathAndQuery := parsedURL.Path
		if parsedURL.Query != "" {
			originalPathAndQuery += "?" + parsedURL.Query
		}

		// Validate base URL with httpx
		validBaseURLs, err := ValidateURLsWithHttpx([]string{baseURL})
		if err != nil {
			LogError("Failed to validate URL with httpx: %v\n", err)
			os.Exit(1)
		}

		// Append original path and query to each valid base URL
		for _, validBaseURL := range validBaseURLs {
			urls = append(urls, validBaseURL+originalPathAndQuery) // Add directly to urls instead of tempURLs
		}
	}

	// Handle URLs from file
	if config.URLsFile != "" {
		content, err := os.ReadFile(config.URLsFile)
		if err != nil {
			LogError("Failed to read URLs file: %v\n", err)
			os.Exit(1)
		}

		fileURLs := strings.Split(strings.TrimSpace(string(content)), "\n")
		for _, u := range fileURLs {
			if u = strings.TrimSpace(u); u != "" {
				// Basic validation first
				if err := validateURL(u); err != nil {
					LogError("Invalid URL in file - %s: %v\n", u, err)
					os.Exit(1)
				}

				// Parse URL to separate base URL and path+query
				parsedURL := rawurlparser.RawURLParse(u)
				if parsedURL == nil {
					LogError("Failed to parse URL: %s\n", u)
					continue
				}

				// Extract base URL (scheme + host)
				baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

				// Combine path and query
				originalPathAndQuery := parsedURL.Path
				if parsedURL.Query != "" {
					originalPathAndQuery += "?" + parsedURL.Query
				}

				// Validate base URL with httpx
				validBaseURLs, err := ValidateURLsWithHttpx([]string{baseURL})
				if err != nil {
					LogError("Failed to validate URL with httpx: %v\n", err)
					continue
				}

				// Append original path and query to each valid base URL
				for _, validBaseURL := range validBaseURLs {
					urls = append(urls, validBaseURL+originalPathAndQuery)
				}
			}
		}
	}

	// Handle substitute hosts file
	if config.SubstituteHostsFile != "" {
		// Parse original URL
		originalURL := rawurlparser.RawURLParse(config.URL)
		if originalURL == nil {
			LogError("Failed to parse target URL\n")
			os.Exit(1)
		}

		// Get original path and query
		originalPathAndQuery := originalURL.Path
		if originalURL.Query != "" {
			originalPathAndQuery += "?" + originalURL.Query
		}

		baseURL := fmt.Sprintf("%s://%s", originalURL.Scheme, originalURL.Host)
		_, err := ValidateURLsWithHttpx([]string{baseURL})
		if err != nil {
			LogError("Failed to validate original URL with httpx: %v\n", err)
			os.Exit(1)
		}

		// Read hosts file
		content, err := os.ReadFile(config.SubstituteHostsFile)
		if err != nil {
			LogError("Failed to read substitute hosts file: %v\n", err)
			os.Exit(1)
		}

		// Process and validate hosts
		var hostsToCheck []string
		for _, host := range strings.Split(strings.TrimSpace(string(content)), "\n") {
			host = strings.TrimSpace(host)
			if host == "" {
				continue
			}

			// If it's already a URL (has scheme), extract the host
			if strings.Contains(host, "://") {
				if parsed := rawurlparser.RawURLParse(host); parsed != nil {
					host = parsed.Host
				}
			}

			// Validate if it's a domain or IP (with optional port)
			if IsIP(host) || IsDNSName(host) {
				hostsToCheck = append(hostsToCheck, host)
			} else {
				LogError("Invalid host in substitute file: %s\n", host)
				continue
			}
		}

		// Validate hosts with httpx
		validHosts, err := ValidateURLsWithHttpx(hostsToCheck)
		if err != nil {
			LogError("Failed to validate hosts with httpx: %v\n", err)
			os.Exit(1)
		}

		// Append original path and query to each valid host
		for _, validHost := range validHosts {
			urls = append(urls, validHost+originalPathAndQuery) // Add directly to urls instead of tempURLs
		}
	}

	// Setup logging
	if config.Verbose {
		log.SetFlags(log.Ltime | log.Lmicroseconds)
	} else {
		log.SetFlags(0)
	}

	// Create output directory in tmp if not specified
	if config.OutDir == "" {
		config.OutDir = filepath.Join(os.TempDir(), fmt.Sprintf("go-bypass-403-%x", time.Now().UnixNano()))
	}

	if err := os.MkdirAll(config.OutDir, 0755); err != nil {
		LogError("Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	// Initialize findings.json file
	outputFile := filepath.Join(config.OutDir, "findings.json")
	initialJSON := struct {
		Scans []interface{} `json:"scans"`
	}{
		Scans: make([]interface{}, 0),
	}

	jsonData, err := json.MarshalIndent(initialJSON, "", "  ")
	if err != nil {
		LogError("Failed to create initial JSON structure: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(outputFile, jsonData, 0644); err != nil {
		LogError("Failed to initialize findings.json: %v\n", err)
		os.Exit(1)
	}

	// Proxy
	if config.Proxy != "" {
		parsedProxy, err := url.Parse(config.Proxy)
		if err != nil {
			LogError("Failed to parse proxy URL: %v", err)
		} else {
			config.ParsedProxy = parsedProxy
		}
	}

	// Banner
	fmt.Print("\n")
	fmt.Printf("\r\033[1;97;45mGo-Bypass-403 v%s\033[0m\n", VERSION)
	fmt.Print("\n")

	// Print configuration
	fmt.Println("Configuration:")
	fmt.Printf("  URL: %s\n", config.URL)
	fmt.Printf("  Using Input File: %s\n", config.URLsFile)
	fmt.Printf("  Using Substitute Hosts File: %s\n", config.SubstituteHostsFile)
	fmt.Printf("  Mode: %s\n", config.Mode)
	fmt.Printf("  Output Directory: %s\n", config.OutDir)
	fmt.Printf("  Output Findings File: %s\n", outputFile)
	fmt.Printf("  Threads: %d\n", config.Threads)
	fmt.Printf("  Timeout: %d seconds\n", config.Timeout)
	fmt.Printf("  Request Delay: %dms\n", config.Delay)
	fmt.Printf("  Filtering HTTP Status Codes: %v\n", config.MatchStatusCodes)
	fmt.Printf("  Verbose mode: %v\n", config.Verbose)
	fmt.Printf("  Debug mode: %v\n", config.Debug)
	fmt.Printf("  Force HTTP/2: %v\n", config.ForceHTTP2)
	if config.SpoofHeader != "" {
		fmt.Printf("  Custom IP Spoofing Headers: %s\n", config.SpoofHeader)
	}
	if config.SpoofIP != "" {
		fmt.Printf("  Custom Spoofing IPs: %s\n", config.SpoofIP)
	}
	if config.Proxy != "" {
		fmt.Printf("  Using proxy: %s\n", config.Proxy)
	}
	fmt.Print("\n")

	// Process URLs
	if len(urls) == 0 {
		LogError("No valid URLs found to scan\n")
		os.Exit(1)
	} else if len(urls) > 0 {
		// Create a map for deduplication
		urlMap := make(map[string]bool)
		var uniqueURLs []string

		for _, u := range urls {
			if !urlMap[u] {
				urlMap[u] = true
				uniqueURLs = append(uniqueURLs, u)
			}
		}

		urls = uniqueURLs
	}

	// Process filtered URLs and start scanning
	LogYellow("[+] Total URLs to be scanned: %d\n", len(urls))

	// Initialize client
	initRawHTTPClient()
	defer globalRawClient.Close()

	// Process filtered URLs and start scanning
	for _, url := range urls {
		config.URL = url
		//fmt.Printf("%s[+] Scanning %s ...%s\n", colorCyan, url, colorReset)

		LogDebug("Processing URL: %s", url)

		results := RunAllBypasses(url)
		var findings []*Result

		// Collect all results first
		for result := range results {
			findings = append(findings, result)
		}

		// Print table header and findings
		if len(findings) > 0 {
			PrintTableHeader(url)
			for _, result := range findings {
				PrintTableRow(result)
			}
			fmt.Printf("\n")

			// Save results to JSON
			if err := SaveResultsToJSON(config.OutDir, url, config.Mode, findings); err != nil {
				LogError("Failed to save JSON results: %v", err)
			}
			LogGreen("[+] Results saved to %s\n", outputFile)
		} else {
			fmt.Printf("\n%sSorry, no bypasses found for %s%s\n\n", colorRed, url, colorReset)
		}
	}
}
