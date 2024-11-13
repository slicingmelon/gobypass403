// utils.go
package main

import (
	"fmt"
	"log"
	"os"
	"strings"
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
)

// LogInfo prints info messages (always shown)
func LogInfo(format string, v ...interface{}) {
	fmt.Printf("[INFO] "+format+"\n", v...)
}

// LogDebug prints debug messages (only shown with -v flag)
func LogDebug(format string, v ...interface{}) {
	if isVerbose {
		fmt.Printf("\033[36m[DEBUG] "+format+"\033[0m\n", v...) // Cyan
	}
}

// LogError prints error messages in red
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
	return payloads, nil
}

// BuildCurlCmd generates a curl command string for the given request parameters
func buildCurlCmd(method, url string, headers map[string]string) string {
	parts := []string{"curl", "-skgi", "--path-as-is"}

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

// Helper function to convert a slice of Header structs to a map
func headersToMap(headers []Header) map[string]string {
	m := make(map[string]string)
	for _, h := range headers {
		m[h.Key] = h.Value
	}
	return m
}

// Helper function to check if a byte is a letter
func isLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
