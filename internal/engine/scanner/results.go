package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

// Result represents a single bypass attempt result
type Result struct {
	TargetURL       string `json:"target_url"`
	BypassModule    string `json:"bypass_module"`
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

// ScanResult represents results for a single URL scan
type ScanResult struct {
	URL         string    `json:"url"`
	BypassModes string    `json:"bypass_modes"`
	ResultsPath string    `json:"results_path"`
	Results     []*Result `json:"results"`
}

// JSONData represents the complete scan results
type JSONData struct {
	Scans []ScanResult `json:"scans"`
}

type ResponseDetails struct {
	StatusCode      int
	ResponsePreview string
	ResponseHeaders string
	ContentType     string
	ContentLength   int64
	ServerInfo      string
	RedirectURL     string
	ResponseBytes   int
	Title           string
}

// PrintTableHeader prints the header for results table
func PrintTableHeader(targetURL string) {
	fmt.Print("\n")
	logger.Teal("[##########] Results for ")
	logger.Yellow(targetURL)
	logger.Teal(" [##########]")

	fmt.Printf("%s [%s] ======================================> %s [%s] [%s] [%s] [%s] [%s]\n",
		logger.Blue("[bypass]"),
		logger.Yellow("[curl poc]"),
		logger.Green("[status]"),
		logger.Purple("[content-length]"),
		logger.Orange("[content-type]"),
		logger.Teal("[title]"),
		logger.Gray("[server]"),
		logger.Pink("[redirect]"))

	fmt.Println(strings.Repeat("-", 120))
}

// PrintTableRow prints a single result row
func PrintTableRow(result *Result) {
	formatValue := func(val string) string {
		if val == "" {
			return "[-]"
		}
		return val
	}

	title := formatValue(result.Title)
	if len(title) > 30 {
		title = title[:27] + "..."
	}

	// Format everything in a single line
	fmt.Printf("%s [%s] ======================================> %s [%s] [%s] [%s] [%s] [%s]\n",
		logger.BlueString("[%s]", result.BypassModule),
		logger.YellowString("%s", result.CurlPocCommand),
		logger.GreenString("[%d]", result.StatusCode),
		logger.PurpleString("[%s]", formatBytes(result.ContentLength)),
		logger.OrangeString("[%s]", formatValue(result.ContentType)),
		logger.TealString("[%s]", title),
		logger.GrayString("[%s]", formatValue(result.ServerInfo)),
		logger.PinkString("[%s]", formatValue(result.RedirectURL)))
}

// AppendResultsToJSON appends scan results to JSON file
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
		data = JSONData{
			Scans: make([]ScanResult, 0),
		}
		logger.LogVerbose("[JSON] Initializing new JSON file")
	} else {
		if err := json.Unmarshal(fileData, &data); err != nil {
			return fmt.Errorf("failed to parse existing JSON: %v", err)
		}
		logger.LogVerbose("[JSON] Read existing JSON file with %d scans", len(data.Scans))
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
		ResultsPath: filepath.Dir(outputFile),
		Results:     cleanFindings,
	}

	data.Scans = append(data.Scans, scan)
	logger.LogVerbose("[JSON] Updated JSON now has %d scans", len(data.Scans))

	// Create a buffered writer
	file, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open JSON file: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode JSON: %v", err)
	}

	return writer.Flush()
}

// Helper function to format bytes
func formatBytes(bytes int64) string {
	if bytes == 0 {
		return "[-]"
	}
	return fmt.Sprintf("%d", bytes)
}

// BuildCurlCmd generates a curl command string for the given request parameters
func BuildCurlCmd(method, url string, headers map[string]string) string {
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
