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

var logger = GB403Logger.NewLogger()

// PrintTableHeader prints the header for results table
func PrintTableHeader(targetURL string) {
	// Title only
	fmt.Println()
	fmt.Println()
	logger.PrintTeal("[##########] Results for ")
	logger.PrintYellow(targetURL)
	logger.PrintTeal(" [##########]")
	fmt.Println()
}

func formatValue(val string) string {
	if val == "" {
		return "[-]"
	}
	return val
}

// PrintTableRow prints a single result row
func PrintTableRow(results []*Result) {
	const rowsPerPage = 50
	pages := (len(results) + rowsPerPage - 1) / rowsPerPage // Calculate total pages

	for page := 0; page < pages; page++ {
		start := page * rowsPerPage
		end := start + rowsPerPage
		if end > len(results) {
			end = len(results)
		}

		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)

		// Configure columns
		t.AppendHeader(table.Row{
			"Module",
			"Curl PoC",
			"Status",
			"Length",
			"Type",
			"Title",
			"Server",
			"Redirect",
		})

		// Calculate max width for Curl PoC based on actual content
		maxCurlWidth := 80 // default
		for _, result := range results {
			if len(result.CurlPocCommand) > maxCurlWidth {
				maxCurlWidth = len(result.CurlPocCommand)
			}
		}

		// Set column configs with dynamic width for Curl PoC
		t.SetColumnConfigs([]table.ColumnConfig{
			{Name: "Module", WidthMax: 20},
			{Name: "Curl PoC", WidthMax: maxCurlWidth + 5}, // Add small padding
			{Name: "Status", Align: text.AlignRight, WidthMax: 6},
			{Name: "Length", Align: text.AlignRight, WidthMax: 10},
			{Name: "Type", WidthMax: 15},
			{Name: "Title", WidthMax: 30},
			{Name: "Server", WidthMax: 20},
			{Name: "Redirect", WidthMax: 40},
		})

		// Add rows for this page
		for _, result := range results[start:end] {
			title := formatValue(result.Title)
			if len(title) > 30 {
				title = title[:27] + "..."
			}

			locationHeader := formatValue(result.RedirectURL)
			if len(locationHeader) > 15 {
				locationHeader = locationHeader[:12] + "..."
			}

			contentType := formatValue(result.ContentType)
			if strings.Contains(contentType, ";") {
				contentType = strings.TrimSpace(strings.Split(contentType, ";")[0])
			}

			t.AppendRow(table.Row{
				text.Colors{text.FgBlue}.Sprint(result.BypassModule),
				text.Colors{text.FgYellow}.Sprint(result.CurlPocCommand),
				text.Colors{text.FgGreen}.Sprintf("%d", result.StatusCode),
				text.Colors{text.FgMagenta}.Sprint(formatBytes(result.ContentLength)),
				text.Colors{text.FgHiYellow}.Sprint(contentType),
				text.Colors{text.FgHiCyan}.Sprint(title),
				text.Colors{text.FgHiBlack}.Sprint(formatValue(result.ServerInfo)),
				text.Colors{text.FgHiMagenta}.Sprint(locationHeader),
			})
		}

		t.SetStyle(table.StyleLight)
		t.Style().Color.Header = text.Colors{text.FgHiCyan, text.Bold}
		t.Style().Options.SeparateRows = true

		if pages > 1 {
			fmt.Printf("\nPage %d/%d\n", page+1, pages)
		}
		fmt.Println(t.Render())

		if page < pages-1 {
			fmt.Println("\nPress Enter to see next page...")
			bufio.NewReader(os.Stdin).ReadBytes('\n')
		}
	}
}

func ProcessResults(results chan *Result, targetURL string, outputFile string) {
	var moduleFindings = make(map[string][]*Result)

	for result := range results {
		if result != nil {
			// Group findings by module
			moduleFindings[result.BypassModule] = append(moduleFindings[result.BypassModule], result)

			// When we have findings for a module, display them
			if len(moduleFindings[result.BypassModule]) > 0 {
				findings := moduleFindings[result.BypassModule]

				fmt.Println()
				PrintTableHeader(targetURL)
				PrintTableRow(findings)

				// Save findings for this module
				if err := AppendResultsToJSON(outputFile, targetURL, result.BypassModule, findings); err != nil {
					logger.LogError("Failed to save findings for %s: %v", targetURL, err)
				}

				// Clear the findings for this module
				delete(moduleFindings, result.BypassModule)
			}
		}
	}
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
