// utils.go
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"math/rand"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/httpx/runner"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
	colorGray   = "\033[90m"
	colorOrange = "\033[38;5;208m"
	colorPink   = "\033[38;5;206m"
	colorTeal   = "\033[38;5;51m"
)

// LogInfo prints info messages (always shown)
func LogInfo(format string, v ...interface{}) {
	fmt.Printf("[INFO] "+format+"\n", v...)
}

// LogVe
func LogVerbose(format string, v ...interface{}) {
	if config.Verbose {
		fmt.Printf("\n"+colorCyan+format+colorReset+"\n", v...) // Cyan
	}
}

// LogDebug (only if -d and color purple)
func LogDebug(format string, v ...interface{}) {
	if config.Debug {
		fmt.Printf("\n"+colorPurple+format+colorReset+"\n", v...) // Purple
	}
}

// Red
func LogError(format string, v ...interface{}) {
	fmt.Printf("\n"+colorRed+"[ERROR] "+format+colorReset+"\n", v...)
}

func LogGreen(format string, v ...interface{}) {
	fmt.Printf("\n\033[32m"+format+"\033[0m\n", v...) // Green
}

func LogBlue(format string, v ...interface{}) {
	fmt.Printf("\n\033[34m"+format+"\033[0m\n", v...) // Blue
}

func LogYellow(format string, v ...interface{}) {
	fmt.Printf("\n\033[93m"+format+"\033[0m\n", v...) // Yellow
}

func LogRed(format string, v ...interface{}) {
	fmt.Printf("\n\033[91m"+format+"\033[0m\n", v...) // Red
}

func LogPurple(format string, v ...interface{}) {
	fmt.Printf(colorPurple+format+colorReset+"\n", v...) // Purple
}

func LogGray(format string, v ...interface{}) {
	fmt.Printf(colorGray+format+colorReset+"\n", v...) // Gray
}

func LogOrange(format string, v ...interface{}) {
	fmt.Printf(colorOrange+format+colorReset+"\n", v...) // Orange
}

func LogPink(format string, v ...interface{}) {
	fmt.Printf(colorPink+format+colorReset+"\n", v...) // Pink
}

func LogTeal(format string, v ...interface{}) {
	fmt.Printf(colorTeal+format+colorReset+"\n", v...) // Teal
}

// Helper function to read payloads from the specified file
func readPayloadsFile(filename string) ([]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var payloads []string
	for _, line := range strings.Split(string(content), "\n") {
		// Trim both spaces and \r\n
		line = strings.TrimSpace(line)
		if line != "" {
			payloads = append(payloads, line)
		}
	}

	return payloads, nil
}

// BuildCurlCmd generates a curl command string for the given request parameters
func buildCurlCmd(method, url string, headers map[string]string) string {
	// Determine curl command based on OS
	curlCmd := "curl"
	if runtime.GOOS == "windows" {
		curlCmd = "curl.exe"
	}

	parts := []string{curlCmd, "-skgi", "--path-as-is"}

	// Add method if not GET
	if method != "GET" {
		parts = append(parts, "-X", method)
	}

	// Add headers
	for k, v := range headers {
		parts = append(parts, fmt.Sprintf("-H '%s: %s'", k, v))
	}

	// Add URL
	parts = append(parts, fmt.Sprintf("'%s'", url))

	return strings.Join(parts, " ")
}

// Helper function to format bytes (so you can see human readable size)
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < 0 {
		return "unknown"
	}
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// Utility functions to print results to the terminal
func PrintTableHeader(targetURL string) {
	fmt.Print("\n")

	fmt.Printf("%s%s[##########] Results for %s%s%s [##########]%s\n",
		colorCyan,
		colorBold,
		colorYellow,
		targetURL,
		colorCyan,
		colorReset)

	fmt.Printf("%s[bypass]%s [%scurl poc%s] ======================================> %s[status]%s [%scontent-length%s] [%scontent-type%s] [%stitle%s] [%sserver%s] [%sredirect%s]\n",
		colorBlue, // bypass
		colorReset,
		colorYellow, // curl poc
		colorReset,
		colorGreen, // status
		colorReset,
		colorPurple, // content-length
		colorReset,
		colorOrange, // content-type (new)
		colorReset,
		colorCyan, // title
		colorReset,
		colorWhite, // server
		colorReset,
		colorRed, // redirect
		colorReset)

	fmt.Println(strings.Repeat("-", 120))
}

func PrintTableRow(result *Result) {
	formatValue := func(val string) string {
		if val == "" {
			return "[-]"
		}
		return val
	}

	// Title might be long, so we'll truncate it if needed
	title := formatValue(result.Title)
	if len(title) > 30 {
		title = title[:27] + "..."
	}

	fmt.Printf("%s[%s]%s [%s%s%s] => %s[%d]%s [%s%s%s] [%s%s%s] [%s%s%s] [%s%s%s] [%s%s%s]\n",
		colorBlue, result.BypassMode, colorReset,
		colorYellow, result.CurlPocCommand, colorReset,
		colorGreen, result.StatusCode, colorReset,
		colorPurple, formatBytes(result.ContentLength), colorReset,
		colorOrange, formatValue(result.ContentType), colorReset,
		colorCyan, title, colorReset,
		colorWhite, formatValue(result.ServerInfo), colorReset,
		colorRed, formatValue(result.RedirectURL), colorReset)
}

// Helper function to save results to JSON file
func SaveResultsToJSON(outputDir string, url string, mode string, findings []*Result) error {
	outputFile := filepath.Join(outputDir, "findings.json")

	// Read existing JSON file
	fileData, err := os.ReadFile(outputFile)
	if err != nil {
		return fmt.Errorf("failed to read JSON file: %v", err)
	}

	var data JSONData
	if err := json.Unmarshal(fileData, &data); err != nil {
		return fmt.Errorf("failed to parse existing JSON: %v", err)
	}

	// Clean up findings
	cleanFindings := make([]*Result, len(findings))
	for i, result := range findings {
		cleanResult := *result
		cleanResult.ResponsePreview = html.UnescapeString(cleanResult.ResponsePreview)
		cleanFindings[i] = &cleanResult
	}

	// Add new scan results
	scan := ScanResult{
		URL:         url,
		BypassModes: mode,
		ResultsPath: outputDir,
		Results:     cleanFindings,
	}

	data.Scans = append(data.Scans, scan)

	// Use custom encoder to fix unicode escapes
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	if err := os.WriteFile(outputFile, buffer.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %v", err)
	}

	return nil
}

func AppendResultsToJSON(outputFile, url, mode string, findings []*Result) error {
	fileLock := &sync.Mutex{}
	fileLock.Lock()
	defer fileLock.Unlock()

	var data JSONData

	// Try to read existing file
	fileData, err := os.ReadFile(outputFile)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to read JSON file: %v", err)
		}
		// File doesn't exist, initialize new data structure
		data = JSONData{
			Scans: make([]ScanResult, 0),
		}
		LogVerbose("[JSON] Initializing new JSON file")
	} else {
		// File exists, parse it
		if err := json.Unmarshal(fileData, &data); err != nil {
			return fmt.Errorf("failed to parse existing JSON: %v", err)
		}
		LogVerbose("[JSON] Read existing JSON file with %d scans", len(data.Scans))
	}

	// Clean up findings
	cleanFindings := make([]*Result, len(findings))
	for i, result := range findings {
		cleanResult := *result
		cleanResult.ResponsePreview = html.UnescapeString(cleanResult.ResponsePreview)
		cleanFindings[i] = &cleanResult
	}

	// Add new scan results
	scan := ScanResult{
		URL:         url,
		BypassModes: mode,
		ResultsPath: config.OutDir,
		Results:     cleanFindings,
	}

	data.Scans = append(data.Scans, scan)
	LogVerbose("[JSON] Updated JSON now has %d scans", len(data.Scans))

	// Open file with write permissions
	file, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open JSON file: %v", err)
	}
	defer file.Close()

	// Create a buffered writer
	writer := bufio.NewWriter(file)

	// Use custom encoder with the buffered writer
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode JSON: %v", err)
	}

	// Flush the buffer to ensure all data is written
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush writer: %v", err)
	}

	return nil
}

// Helper function to convert a slice of Header structs to a map
func headersToMap(headers []Header) map[string]string {
	m := make(map[string]string)
	for _, h := range headers {
		m[h.Key] = h.Value
	}
	return m
}

// Helper function to format headers for logging
func formatHeaders(headers []Header) string {
	if len(headers) == 0 {
		return ""
	}
	return fmt.Sprintf(" [Headers: %v]", headers)
}

// Helper function to extract title from response body
func extractTitle(body string) string {
	var titleRegex = regexp.MustCompile(`(?i)<title>(.*?)</title>`)

	matches := titleRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// Helper function to check if a byte is a letter
func isLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// Helper function to generate random strings
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// ReplaceNth replaces the nth occurrence of old with new in s
func ReplaceNth(s, old, new string, n int) string {
	if n < 1 {
		return s
	}

	count := 0
	pos := 0

	// Find the nth occurrence
	for count < n {
		nextPos := strings.Index(s[pos:], old)
		if nextPos == -1 {
			// Not enough occurrences found
			return s
		}

		pos += nextPos
		count++

		if count < n {
			pos += len(old) // Move past current occurrence
		}
	}

	// Replace the nth occurrence
	return s[:pos] + new + s[pos+len(old):]
}

// ----------------------------------------------------------------//
// URL Validation Stuff//
// Custom URL Validation, HTTPX probes and more //

// RFC 1035
var rxDNSName = regexp.MustCompile(`^([a-zA-Z0-9_]{1}[a-zA-Z0-9\-._]{0,61}[a-zA-Z0-9]{1}\.)*` +
	`([a-zA-Z0-9_]{1}[a-zA-Z0-9\-._]{0,61}[a-zA-Z0-9]{1}\.?)$`)

func IsIP(str string) bool {
	LogDebug("[DEBUG] Checking if string is IP: %q", str)

	// Split host and port
	host, port, err := net.SplitHostPort(str)
	if err != nil {
		LogDebug("[DEBUG] SplitHostPort failed, using full string: %v", err)
		return net.ParseIP(str) != nil
	}

	LogDebug("[DEBUG] Split host: %q port: %q", host, port)
	return net.ParseIP(host) != nil
}

// Update IsDNSName with debugging
func IsDNSName(str string) bool {
	LogDebug("[DEBUG] Checking if string is DNS name: %q", str)

	host, port, err := net.SplitHostPort(str)
	if err != nil {
		host = str
		LogDebug("[DEBUG] Using full string as hostname: %q", host)
	} else {
		LogDebug("[DEBUG] Split host: %q port: %q", host, port)
	}

	if host == "" {
		LogDebug("[DEBUG] Empty hostname")
		return false
	}

	if len(strings.Replace(host, ".", "", -1)) > 255 {
		LogDebug("[DEBUG] Hostname too long (>255 chars)")
		return false
	}

	LogDebug("[DEBUG] DNS regex match result: %v", rxDNSName.MatchString(host))
	return !IsIP(host) && rxDNSName.MatchString(host)
}

// HttpxResult -- detailed information about a probed URL
// HttpxResult -- detailed information about a probed URL
type HttpxResult struct {
	Host    string            // Base hostname without port (extracted from URL)
	Ports   map[string]string // Map of port -> scheme (e.g., "80" -> "http", "443" -> "https")
	Schemes []string          // Available schemes (http, https)
	IPv4    []string          // List of IPv4 addresses
	IPv6    []string          // List of IPv6 addresses
	CNAMEs  []string          // List of CNAMEs
}

// ValidateURLsWithHttpx probes URLs and returns detailed information
func ValidateURLsWithHttpx(urls []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	LogDebug("[DEBUG] Starting URL validation for %d URLs", len(urls))

	var wg sync.WaitGroup
	errChan := make(chan error, len(urls))

	// Process URLs in batches
	batchSize := 5
	for i := 0; i < len(urls); i += batchSize {
		end := i + batchSize
		if end > len(urls) {
			end = len(urls)
		}
		batch := urls[i:end]

		wg.Add(1)
		go func(urlBatch []string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				options := runner.Options{
					Methods:          "HEAD",
					InputTargetHost:  goflags.StringSlice(urlBatch),
					RandomAgent:      true,
					NoFallback:       true,
					NoFallbackScheme: true,
					Threads:          2,
					ProbeAllIPS:      false,
					OutputIP:         true,
					OutputCName:      true,
					Timeout:          30,
					Retries:          3,
					ZTLS:             true,
					Debug:            config.Debug,
					Resolvers: []string{
						"1.1.1.1:53", "1.0.0.1:53",
						"9.9.9.10:53", "8.8.4.4:53",
					},
					OnResult: func(r runner.Result) {
						if r.Err != nil || r.URL == "" {
							LogVerbose("Skipping invalid result: %v", r.Err)
							return
						}

						LogVerbose("Processing result:\n"+
							"URL: %s\n"+
							"Host: %s\n"+
							"Port: %s\n"+
							"Scheme: %v\n"+
							"IPs: %v\n"+
							"CNAMEs: %v\n",
							r.URL, r.Host, r.Port, r.Scheme, r.A, r.CNAMEs)

						if err := globalHttpxResults.UpdateHost(r); err != nil {
							LogVerbose("Failed to update host cache: %v", err)
						}
					},
				}

				httpxRunner, err := runner.New(&options)
				if err != nil {
					errChan <- fmt.Errorf("failed to create httpx runner: %v", err)
					return
				}
				defer httpxRunner.Close()

				LogVerbose("Starting httpx enumeration for batch")
				httpxRunner.RunEnumeration()
			}
		}(batch)
	}

	// Wait for all goroutines to complete or context to cancel
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		close(errChan)
		for err := range errChan {
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// ----------------------------------------------------------------//
// ProgressCounter //
// Custom code to show progress on the current bypass mode
type ProgressCounter struct {
	total     int
	current   int
	mode      string
	mu        sync.Mutex
	cancelled bool
}

func (pc *ProgressCounter) markAsCancelled() {
	pc.mu.Lock()
	pc.cancelled = true
	fmt.Printf("\r%s[%s]%s %sCancelled at:%s %s%d%s/%s%d%s (%s%.1f%%%s) - %s%s%s\n",
		colorCyan, pc.mode, colorReset,
		colorRed, colorReset,
		colorRed, pc.current, colorReset,
		colorGreen, pc.total, colorReset,
		colorRed, float64(pc.current)/float64(pc.total)*100, colorReset,
		colorYellow, "Permanent error detected - Skipping current job", colorReset,
	)
	pc.mu.Unlock()
}

func (pc *ProgressCounter) increment() {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if pc.cancelled {
		return
	}

	pc.current++

	// Calculate percentage
	percentage := float64(pc.current) / float64(pc.total) * 100

	// Color for current count based on progress
	var currentColor string
	switch {
	case percentage <= 25:
		currentColor = colorRed
	case percentage <= 50:
		currentColor = colorOrange
	case percentage <= 75:
		currentColor = colorYellow
	default:
		currentColor = colorGreen
	}

	// Print URL only once at the start
	if pc.current == 1 {
		fmt.Printf("%s[+] Scanning %s ...%s\n", colorCyan, config.URL, colorReset)
	}

	// Print progress on same line with your color scheme
	fmt.Printf("\r%s[%s]%s %sProgress:%s %s%d%s/%s%d%s (%s%.1f%%%s)",
		colorCyan, pc.mode, colorReset,
		colorTeal, colorReset,
		currentColor, pc.current, colorReset,
		colorGreen, pc.total, colorReset,
		currentColor, percentage, colorReset,
	)
}

func (pc *ProgressCounter) isCancelled() bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.cancelled
}
