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

// readAndValidateHosts reads hosts from file and validates them
func readAndValidateHosts(hostsFile string) ([]string, error) {
	content, err := os.ReadFile(hostsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read substitute hosts file: %v", err)
	}

	var hostsToCheck []string
	for _, host := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}

		// If it's already a URL (has scheme), extract the host
		if strings.Contains(host, "://") {
			if parsed, err := rawurlparser.RawURLParse(host); err == nil {
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

	return hostsToCheck, nil
}

// ProcessInputURLs handles all URL input methods and returns validated URLs
func ProcessInputURLs() ([]string, error) {
	if config.URL == "" && config.URLsFile == "" {
		return nil, fmt.Errorf("either Target URL (-u) or URLs file (-l) is required")
	}

	// Validate input combinations
	if config.SubstituteHostsFile != "" {
		if config.URL == "" {
			return nil, fmt.Errorf("a target URL (-u) is required when using substitute hosts file")
		}
		if config.URLsFile != "" {
			return nil, fmt.Errorf("cannot use both URLs file (-l) and substitute hosts file")
		}
	}

	var hostsToProbe []string
	var originalPaths = make(map[string]string) // map[host]pathAndQuery

	// Process direct URL input
	if config.URL != "" {
		parsedURL, err := rawurlparser.RawURLParse(config.URL)
		if err != nil {
			return nil, fmt.Errorf("invalid URL: %v", err)
		}
		hostsToProbe = append(hostsToProbe, parsedURL.Host)
		originalPaths[parsedURL.Host] = getPathAndQuery(parsedURL)
	}

	// Process URLs file
	if config.URLsFile != "" {
		hosts, paths, err := processURLsFromFile(config.URLsFile)
		if err != nil {
			return nil, err
		}
		hostsToProbe = append(hostsToProbe, hosts...)
		for h, p := range paths {
			originalPaths[h] = p
		}
	}

	// Process substitute hosts
	if config.SubstituteHostsFile != "" {
		hosts, err := readAndValidateHosts(config.SubstituteHostsFile)
		if err != nil {
			return nil, err
		}
		// Use original URL's path for all substitute hosts
		parsedURL, _ := rawurlparser.RawURLParse(config.URL)
		path := getPathAndQuery(parsedURL)
		hostsToProbe = append(hostsToProbe, hosts...)
		for _, h := range hosts {
			originalPaths[h] = path
		}
	}

	// Probe hosts with httpx
	if err := FastProbeURLs(hostsToProbe); err != nil {
		return nil, fmt.Errorf("httpx probing failed: %v", err)
	}

	// Construct final URLs from cache results
	var finalURLs []string
	for host, path := range originalPaths {
		if result, exists := globalProbeURLResults.Get(host); exists {
			// Iterate through port-scheme mappings
			for port, scheme := range result.Ports {
				baseURL := constructBaseURL(scheme, result.Hostname, port)
				finalURL := baseURL + path
				LogDebug("[DEBUG] Constructed URL: %s (scheme=%s, host=%s, port=%s, path=%s)",
					finalURL, scheme, result.Hostname, port, path)
				finalURLs = append(finalURLs, finalURL)
			}
		} else {
			LogDebug("[DEBUG] No httpx results found for host: %s", host)
		}
	}

	return deduplicateURLs(finalURLs), nil
}

// Helper functions
func processURLsFromFile(filename string) ([]string, map[string]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read URLs file: %v", err)
	}

	var hosts []string
	paths := make(map[string]string)

	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}

		parsedURL, err := rawurlparser.RawURLParse(line)
		if err != nil {
			LogError("Invalid URL in file: %s", line)
			continue
		}

		hosts = append(hosts, parsedURL.Host)
		paths[parsedURL.Host] = getPathAndQuery(parsedURL)
	}

	return hosts, paths, nil
}

func constructBaseURL(scheme, host, port string) string {
	// Default ports should be omitted
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		LogVerbose("[VERBOSE] Using default port for %s://%s (port %s)", scheme, host, port)
		return fmt.Sprintf("%s://%s", scheme, host)
	}

	// Include non-default ports in the URL
	baseURL := fmt.Sprintf("%s://%s:%s", scheme, host, port)
	LogVerbose("[VERBOSE] Using non-default port: %s", baseURL)
	return baseURL
}

func getPathAndQuery(parsedURL *rawurlparser.RawURL) string {
	pathAndQuery := parsedURL.Path
	if parsedURL.Query != "" {
		pathAndQuery += "?" + parsedURL.Query
	}
	return pathAndQuery
}

func deduplicateURLs(urls []string) []string {
	urlMap := make(map[string]bool)
	var uniqueURLs []string

	LogVerbose("Processing URLs for deduplication:")
	for _, u := range urls {
		if !urlMap[u] {
			urlMap[u] = true
			uniqueURLs = append(uniqueURLs, u)
			LogVerbose("Added unique URL: %s", u)
		}
	}

	LogVerbose("Final unique URLs (%d):", len(uniqueURLs))
	for i, u := range uniqueURLs {
		LogVerbose("%d. %s", i+1, u)
	}

	return uniqueURLs
}

// PrintConfiguration //
// ---//
func PrintConfiguration() {
	outputFile := filepath.Join(config.OutDir, "findings.json")

	fmt.Printf("%sConfiguration:%s\n", colorPink, colorReset)
	fmt.Printf("  %sURL:%s %s%s%s\n", colorCyan, colorReset, colorYellow, config.URL, colorReset)
	fmt.Printf("  %sUsing Input File:%s %s%s%s\n", colorCyan, colorReset, colorYellow, config.URLsFile, colorReset)
	fmt.Printf("  %sUsing Substitute Hosts File:%s %s%s%s\n", colorCyan, colorReset, colorYellow, config.SubstituteHostsFile, colorReset)
	fmt.Printf("  %sMode:%s %s%s%s\n", colorCyan, colorReset, colorYellow, config.Mode, colorReset)
	fmt.Printf("  %sOutput Directory:%s %s%s%s\n", colorCyan, colorReset, colorYellow, config.OutDir, colorReset)
	fmt.Printf("  %sOutput Findings File:%s %s%s%s\n", colorCyan, colorReset, colorYellow, outputFile, colorReset)
	fmt.Printf("  %sThreads:%s %s%d%s\n", colorCyan, colorReset, colorYellow, config.Threads, colorReset)
	fmt.Printf("  %sTimeout:%s %s%d seconds%s\n", colorCyan, colorReset, colorYellow, config.Timeout, colorReset)
	fmt.Printf("  %sRequest Delay:%s %s%dms%s\n", colorCyan, colorReset, colorYellow, config.Delay, colorReset)
	fmt.Printf("  %sFiltering HTTP Status Codes:%s %s%v%s\n", colorCyan, colorReset, colorYellow, config.MatchStatusCodes, colorReset)
	fmt.Printf("  %sVerbose mode:%s %s%v%s\n", colorCyan, colorReset, colorYellow, config.Verbose, colorReset)
	fmt.Printf("  %sDebug mode:%s %s%v%s\n", colorCyan, colorReset, colorYellow, config.Debug, colorReset)
	fmt.Printf("  %sTrace Requests:%s %s%v%s\n", colorCyan, colorReset, colorYellow, config.TraceRequests, colorReset)
	fmt.Printf("  %sForce HTTP/2:%s %s%v%s\n", colorCyan, colorReset, colorYellow, config.ForceHTTP2, colorReset)
	fmt.Printf("  %sFollow Redirects:%s %s%v%s\n", colorCyan, colorReset, colorYellow, config.FollowRedirects, colorReset)

	// Optional configurations
	if config.SpoofHeader != "" {
		fmt.Printf("  %sCustom IP Spoofing Headers:%s %s%s%s\n", colorCyan, colorReset, colorYellow, config.SpoofHeader, colorReset)
	}
	if config.SpoofIP != "" {
		fmt.Printf("  %sCustom Spoofing IPs:%s %s%s%s\n", colorCyan, colorReset, colorYellow, config.SpoofIP, colorReset)
	}
	if config.Proxy != "" {
		fmt.Printf("  %sUsing proxy:%s %s%s%s\n", colorCyan, colorReset, colorYellow, config.Proxy, colorReset)
	}

	fmt.Print("\n")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Print("\n")
}

// -------------------------------------------------------------------------------------//
// Main Function //
func main() {
	flags := []multiFlag{
		{name: "u,url", usage: "Target URL (example: https://cms.facebook.com/login)", value: &config.URL},
		{name: "l,urls-file", usage: "File containing list of target URLs (one per line)", value: &config.URLsFile},
		{name: "shf,substitute-hosts-file", usage: "File containing a list of hosts to substitute target URL's hostname (mostly used in CDN bypasses by providing a list of CDNs)", value: &config.SubstituteHostsFile},
		{name: "m,mode", usage: "Bypass mode (all, mid_paths, end_paths, case_substitution, char_encode, http_headers_scheme, http_headers_ip, http_headers_port, http_headers_url, http_host)", value: &config.Mode, defVal: "all"},
		{name: "o,outdir", usage: "Output directory", value: &config.OutDir},
		{name: "t,threads", usage: "Number of concurrent threads)", value: &config.Threads, defVal: 15},
		{name: "T,timeout", usage: "Timeout in seconds", value: &config.Timeout, defVal: 15},
		{name: "delay", usage: "Delay between requests in milliseconds (Default: 150ms)", value: &config.Delay, defVal: 150},
		{name: "v,verbose", usage: "Verbose output", value: &config.Verbose, defVal: false},
		{name: "d,debug", usage: "Debug mode with request canaries", value: &config.Debug, defVal: false},
		{name: "trace", usage: "Trace HTTP requests", value: &config.TraceRequests, defVal: false},
		{name: "mc,match-status-code", usage: "Only save results matching these HTTP status codes (example: -mc 200,301,500). Default: 200", value: &config.MatchStatusCodesStr},
		{name: "http2", usage: "Force attempt requests on HTTP2", value: &config.ForceHTTP2, defVal: false},
		{name: "x,proxy", usage: "Proxy URL (format: http://proxy:port)", value: &config.Proxy},
		{name: "spoof-header", usage: "Add more headers used to spoof IPs (example: X-SecretIP-Header,X-GO-IP)", value: &config.SpoofHeader},
		{name: "spoof-ip", usage: "Add more spoof IPs (example: 10.10.20.20,172.16.30.10)", value: &config.SpoofIP},
		{name: "fr,follow-redirects", usage: "Follow HTTP redirects", value: &config.FollowRedirects, defVal: false},
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

	// Validate bypass mode and print helper if invalid
	if err := validateMode(config.Mode); err != nil {
		os.Exit(1)
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

	// Initialize findings.json file
	outputFile := filepath.Join(config.OutDir, "findings.json")
	initialJSON := JSONData{
		Scans: make([]ScanResult, 0),
	}

	if err := os.MkdirAll(config.OutDir, 0755); err != nil {
		LogError("Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	jsonData, err := json.MarshalIndent(initialJSON, "", "  ")
	if err != nil {
		LogError("Failed to create initial JSON structure: %v\n", err)
		os.Exit(1)
	}

	// Write the initial JSON structure to file
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

	// Print Banner //
	fmt.Print("\n")
	fmt.Printf("\033[1;97;45mGo-Bypass-403 v%s\033[0m\n", VERSION)
	fmt.Print("\n")

	// Validate input URL(s)
	// Process probed URLs and start scanning
	urls, err := ProcessInputURLs()
	if err != nil {
		LogError("Failed to process input URLs: %v\n", err)
		os.Exit(1)
	}

	// Print configuration
	PrintConfiguration()

	LogYellow("[+] Total URLs to be scanned: %d\n", len(urls))

	for _, url := range urls {
		LogVerbose("Processing URL: %s", url)

		results := RunAllBypasses(url)
		var findings []*Result
		for result := range results {
			findings = append(findings, result)
		}

		// Process and save findings
		if len(findings) > 0 {
			PrintTableHeader(url)
			for _, result := range findings {
				PrintTableRow(result)
			}
			fmt.Printf("\n")

			outputFile := filepath.Join(config.OutDir, "findings.json")
			if err := AppendResultsToJSON(outputFile, url, config.Mode, findings); err != nil {
				LogError("Failed to save JSON results: %v", err)
			} else {
				LogGreen("[+] Results appended to %s\n", outputFile)
			}
		} else {
			LogOrange("\n[!] Sorry, no bypasses found for %s\n", url)
		}
	}

	// Clean up global cache
	if globalProbeURLResults != nil {
		globalProbeURLResults.Purge()
	}

}
