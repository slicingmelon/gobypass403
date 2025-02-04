package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
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
	maxStatusWidth int
	maxLengthWidth int
	maxContentType int
	maxTitleWidth  int
	maxServerWidth int
	hasServer      bool
}

func analyzeResults(results []*Result) columnStats {
	stats := columnStats{}

	for _, result := range results {
		// Module width - exact width of the bypass module name
		stats.maxModuleWidth = max(stats.maxModuleWidth, len(result.BypassModule))

		// Curl command width - exact width of the curl command
		stats.maxCurlWidth = max(stats.maxCurlWidth, len(result.CurlPocCommand))

		// Status width - width of the status code as string
		stats.maxStatusWidth = max(stats.maxStatusWidth, len(fmt.Sprintf("%d", result.StatusCode)))

		// Length width - width of the formatted content length
		stats.maxLengthWidth = max(stats.maxLengthWidth, len(FormatBytesH(result.ContentLength)))

		// Content Type width
		contentType := formatContentType(result.ContentType)
		stats.maxContentType = max(stats.maxContentType, len(contentType))

		// Title width
		stats.maxTitleWidth = max(stats.maxTitleWidth, len(result.Title))

		// Server width
		if result.ServerInfo != "" {
			stats.hasServer = true
			stats.maxServerWidth = max(stats.maxServerWidth, len(result.ServerInfo))
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
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		width = 80
	}

	// Base headers
	tableHeaders := []interface{}{
		"Module",
		"Curl PoC",
		"Status",
		"Length",
		"Type",
		"Title",
	}

	// Add server header if needed
	if stats.hasServer {
		tableHeaders = append(tableHeaders, "Server")
	}

	// Calculate available width for curl command
	fixedWidth := stats.maxModuleWidth + // Module
		stats.maxStatusWidth + // Status
		stats.maxLengthWidth + // Length
		stats.maxContentType + // Type
		stats.maxTitleWidth + // Title
		(6 * 3) // Padding and borders between columns

	if stats.hasServer {
		fixedWidth += stats.maxServerWidth + 3 // Add server width and its padding
	}

	// Adjust curl width to fit terminal
	curlWidth := stats.maxCurlWidth
	if fixedWidth+curlWidth > width {
		curlWidth = width - fixedWidth - 5 // -5 for safety margin
	}

	// Configure columns with exact widths
	columns := []table.ColumnConfig{
		{Name: "MODULE", WidthMax: stats.maxModuleWidth, WidthMin: stats.maxModuleWidth},
		{Name: "CURL POC", WidthMax: curlWidth, WidthMin: curlWidth},
		{Name: "STATUS", WidthMax: stats.maxStatusWidth, WidthMin: stats.maxStatusWidth},
		{Name: "LENGTH", WidthMax: stats.maxLengthWidth, WidthMin: stats.maxLengthWidth},
		{Name: "TYPE", WidthMax: stats.maxContentType, WidthMin: stats.maxContentType},
		{Name: "TITLE", WidthMax: stats.maxTitleWidth, WidthMin: stats.maxTitleWidth},
	}

	if stats.hasServer {
		columns = append(columns, table.ColumnConfig{
			Name:     "SERVER",
			WidthMax: stats.maxServerWidth,
			WidthMin: stats.maxServerWidth,
		})
	}

	// Set styling
	t.SetStyle(table.StyleLight)
	t.Style().Color.Header = text.Colors{text.FgHiCyan, text.Bold}
	t.Style().Options.SeparateRows = true
	t.Style().Options.DrawBorder = true
	t.Style().Box.PaddingLeft = ""
	t.Style().Box.PaddingRight = ""

	t.SetColumnConfigs(columns)
	t.AppendHeader(tableHeaders)

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
	if bytes <= 0 {
		return "[-]"
	}
	return fmt.Sprintf("%d", bytes)
}

// Helper function to format bytes (so you can see human readable size)
func FormatBytesH(bytes int64) string {
	if bytes <= 0 {
		return "[-]"
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
