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

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
	"golang.org/x/term"
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
	// Title only
	fmt.Println()
	fmt.Println()
	GB403Logger.PrintGreen("[##########] Results for %s", targetURL)
	GB403Logger.PrintYellow("%s\n", targetURL)
	GB403Logger.PrintGreen("[##########]")
	fmt.Println()
}

func formatValue(val string) string {
	if val == "" {
		return "[-]"
	}
	return val
}

type columnStats struct {
	maxModuleWidth int
	maxCurlWidth   int
	maxContentType int
	maxTitleLen    int
	hasServer      bool
}

func analyzeResults(results []*Result) columnStats {
	stats := columnStats{}

	// Analyze all results for maximum widths
	for _, result := range results {
		// Module width
		if len(result.BypassModule) > stats.maxModuleWidth {
			stats.maxModuleWidth = len(result.BypassModule)
		}

		// Curl command width
		if len(result.CurlPocCommand) > stats.maxCurlWidth {
			stats.maxCurlWidth = len(result.CurlPocCommand)
		}

		// Content Type width (up to semicolon)
		contentType := formatContentType(result.ContentType)
		if len(contentType) > stats.maxContentType {
			stats.maxContentType = len(contentType)
		}

		// Title length (up to 15 chars)
		if len(result.Title) > stats.maxTitleLen {
			stats.maxTitleLen = min(len(result.Title), 15)
		}

		// Check if any result has server info
		if result.ServerInfo != "" {
			stats.hasServer = true
		}
	}

	return stats
}

// PrintTableRow prints a single result row
func PrintTableRow(results []*Result) {
	stats := analyzeResults(results)

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)

	// Get terminal width
	width := 80
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
		width = w
	}

	// Base headers
	headers := []interface{}{
		"Module",
		"Curl PoC",
		"Status",
		"Length",
		"Type",
		"Title",
	}

	// Calculate column widths
	moduleWidth := min(stats.maxModuleWidth, 15) // +2 for padding
	statusWidth := 3                             // Always 3 digits
	lengthWidth := 8                             // Enough for formatted sizes
	typeWidth := min(stats.maxContentType, 12)
	titleWidth := min(stats.maxTitleLen, 15)
	serverWidth := 12

	// Calculate remaining width for CURL POC
	reservedWidth := moduleWidth + statusWidth + lengthWidth + typeWidth + titleWidth
	if stats.hasServer {
		reservedWidth += serverWidth
		headers = append(headers, "Server")
	}

	curlWidth := min(stats.maxCurlWidth, width-reservedWidth-5) // -5 for padding and borders

	// Configure columns
	columns := []table.ColumnConfig{
		{Name: "MODULE", WidthMax: moduleWidth, WidthMin: moduleWidth},
		{Name: "CURL POC", WidthMax: curlWidth, WidthMin: curlWidth / 2},
		{Name: "STATUS", WidthMax: statusWidth, WidthMin: statusWidth},
		{Name: "LENGTH", WidthMax: lengthWidth, WidthMin: lengthWidth},
		{Name: "TYPE", WidthMax: typeWidth, WidthMin: typeWidth},
		{Name: "TITLE", WidthMax: titleWidth, WidthMin: titleWidth},
	}

	if stats.hasServer {
		columns = append(columns, table.ColumnConfig{
			Name:     "SERVER",
			WidthMax: serverWidth,
			WidthMin: serverWidth,
		})
	}

	// Set styling
	t.SetStyle(table.StyleLight)
	t.Style().Color.Header = text.Colors{text.FgHiCyan, text.Bold}
	t.Style().Options.SeparateRows = true
	t.Style().Options.DrawBorder = true
	t.Style().Box.PaddingLeft = " "
	t.Style().Box.PaddingRight = " "

	t.SetColumnConfigs(columns)
	t.AppendHeader(headers)

	// Add rows
	for _, result := range results {
		row := []interface{}{
			text.Colors{text.FgBlue}.Sprint(result.BypassModule),
			text.Colors{text.FgYellow}.Sprint(result.CurlPocCommand),
			text.Colors{text.FgGreen}.Sprintf("%d", result.StatusCode),
			text.Colors{text.FgMagenta}.Sprint(FormatBytesH(result.ContentLength)),
			text.Colors{text.FgHiYellow}.Sprint(formatContentType(result.ContentType)),
			text.Colors{text.FgHiCyan}.Sprint(formatValue(result.Title)),
		}

		if stats.hasServer {
			row = append(row, text.Colors{text.FgHiBlack}.Sprint(formatValue(result.ServerInfo)))
		}

		t.AppendRow(row)
	}

	t.Render()
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
		GB403Logger.Verbose().Msgf("[JSON] Initializing new JSON file")
	} else {
		if err := json.Unmarshal(fileData, &data); err != nil {
			return fmt.Errorf("failed to parse existing JSON: %v", err)
		}
		GB403Logger.Verbose().Msgf("[JSON] Read existing JSON file with %d scans", len(data.Scans))
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
	GB403Logger.Verbose().Msgf("[JSON] Updated JSON now has %d scans", len(data.Scans))

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

func formatContentType(contentType string) string {
	if contentType == "" {
		return "[-]"
	}
	if strings.Contains(contentType, ";") {
		return strings.TrimSpace(strings.Split(contentType, ";")[0])
	}
	return contentType
}

// Helper function to format bytes
func formatBytes(bytes int64) string {
	if bytes == 0 {
		return "[-]"
	}
	return fmt.Sprintf("%d", bytes)
}

// Helper function to format bytes (so you can see human readable size)
func FormatBytesH(bytes int64) string {
	if bytes == 0 {
		return "[-]"
	}
	if bytes < 0 {
		return "unknown"
	}

	const unit = 1024
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

// BuildCurlCmd generates a curl command string for the given request parameters
// deprecated
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
