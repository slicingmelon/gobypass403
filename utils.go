// utils.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"math/rand"
)

func init() {
	log.SetFlags(0)
	log.SetOutput(os.Stderr)
}

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

// LogDebug (only if -v and color cyan)
func LogDebug(format string, v ...interface{}) {
	if isVerbose {
		fmt.Printf("\033[36m[DEBUG] "+format+"\033[0m\n", v...) // Cyan
	}
}

// LogError (red)
func LogError(format string, v ...interface{}) {
	fmt.Printf("\033[31m[ERROR] "+format+"\033[0m\n", v...) // Red
}

func LogGreen(format string, v ...interface{}) {
	fmt.Printf("\033[32m"+format+"\033[0m\n", v...) // Green
}

func LogBlue(format string, v ...interface{}) {
	fmt.Printf("\033[34m"+format+"\033[0m\n", v...) // Blue
}

func LogYellow(format string, v ...interface{}) {
	fmt.Printf("\033[93m"+format+"\033[0m\n", v...) // Yellow
}

func LogRed(format string, v ...interface{}) {
	fmt.Printf("\033[91m"+format+"\033[0m\n", v...) // Red
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

// SetVerbose
func SetVerbose(verbose bool) {
	isVerbose = verbose
}

// Helper function to read payloads from the specified file
func readPayloadsFile(filename string) ([]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	payloads := strings.Split(strings.TrimSpace(string(content)), "\n")

	LogYellow("\n[+] Read %d payloads from file %s", len(payloads), filename)

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

	fmt.Printf("%s[bypass]%s [%scurl poc%s] ======================================> %s[status]%s [%sresp bytes%s] [%stitle%s] [%sserver%s] [%sredirect%s]\n",
		colorBlue, // bypass
		colorReset,
		colorYellow, // curl poc
		colorReset,
		colorGreen, // status
		colorReset,
		colorPurple, // bytes
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

	// Format the row with colors matching the header
	fmt.Printf("%s[%s]%s [%s%s%s] => %s[%d]%s [%s%s%s] [%s%s%s] [%s%s%s] [%s%s%s]\n",
		colorBlue, result.BypassMode, colorReset,
		colorYellow, result.CurlPocCommand, colorReset,
		colorGreen, result.StatusCode, colorReset,
		colorPurple, formatBytes(int64(result.ResponseBytes)), colorReset,
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

	var data struct {
		Scans []interface{} `json:"scans"`
	}

	if err := json.Unmarshal(fileData, &data); err != nil {
		return fmt.Errorf("failed to parse existing JSON: %v", err)
	}

	// Clean up
	cleanFindings := make([]*Result, len(findings))
	for i, result := range findings {
		// Create a copy of the result
		cleanResult := *result

		cleanResult.ResponsePreview = html.UnescapeString(cleanResult.ResponsePreview)

		cleanFindings[i] = &cleanResult
	}

	// Add new scan results
	scan := struct {
		URL         string    `json:"url"`
		BypassModes string    `json:"bypass_modes"`
		ResultsPath string    `json:"results_path"`
		Results     []*Result `json:"results"`
	}{
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
