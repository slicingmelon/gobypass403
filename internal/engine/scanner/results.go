package scanner

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pterm/pterm"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

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
	ResponseTime    int64  `json:"response_time"`
	DebugToken      string `json:"debug_token"`
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
	ResponseTime    int64
	DebugToken      string
}

// getTableHeader returns the header row for the results table
func getTableHeader() []string {
	return []string{
		"Module",
		"Curl CMD",
		"Status",
		"Length",
		"Type",
		"Title",
		"Server",
	}
}

// getTableRows converts results to table rows, sorted by status code
func getTableRows(results []*Result) [][]string {
	// Sort results by status code
	sort.Slice(results, func(i, j int) bool {
		return results[i].StatusCode < results[j].StatusCode
	})

	rows := make([][]string, len(results))
	for i, result := range results {
		rows[i] = []string{
			result.BypassModule,
			result.CurlPocCommand,
			strconv.Itoa(result.StatusCode),
			FormatBytes(int64(result.ResponseBytes)),
			formatContentType(result.ContentType),
			formatValue(result.Title),
			formatValue(result.ServerInfo),
		}
	}
	return rows
}

func PrintResultsTable(targetURL string, results []*Result) {
	if len(results) == 0 {
		return
	}

	// fancy table title
	pterm.DefaultHeader.WithBackgroundStyle(pterm.NewStyle(pterm.BgGreen)).
		Println("Results for " + targetURL)

	tableData := pterm.TableData{getTableHeader()}
	for _, row := range getTableRows(results) {
		tableData = append(tableData, row)
	}

	// Render table
	time.Sleep(500 * time.Millisecond)
	table := pterm.DefaultTable.
		WithHasHeader().
		WithBoxed().
		WithData(tableData)

	output, err := table.Srender()
	if err != nil {
		return
	}

	// Print the rendered table
	fmt.Println(output)
}

// Helper functions
func formatValue(val string) string {
	if val == "" {
		return "[-]"
	}
	return val
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

func FormatBytes(bytes int64) string {
	if bytes <= 0 {
		return "[-]"
	}
	return strconv.FormatInt(bytes, 10) // + " B"
}

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

// AppendResultsToJSON appends scan results to JSON file
func AppendResultsToJSON(outputFile, url, mode string, findings []*Result) error {
	fileLock := &sync.Mutex{}
	fileLock.Lock()
	defer fileLock.Unlock()

	var data JSONData

	// Read existing file
	fileData, err := os.ReadFile(outputFile)
	if err == nil {
		if err := json.Unmarshal(fileData, &data); err != nil {
			return fmt.Errorf("failed to parse existing JSON: %v", err)
		}
	}

	// Find existing scan for this URL
	var scan *ScanResult
	for i := range data.Scans {
		if data.Scans[i].URL == url {
			scan = &data.Scans[i]
			break
		}
	}

	// Create new scan if none exists
	if scan == nil {
		data.Scans = append(data.Scans, ScanResult{
			URL:         url,
			BypassModes: mode,
			ResultsPath: filepath.Dir(outputFile),
			Results:     []*Result{},
		})
		scan = &data.Scans[len(data.Scans)-1]
	}

	// Merge results
	cleanFindings := make([]*Result, len(findings))
	for i, result := range findings {
		cleanResult := *result
		cleanResult.ResponsePreview = html.UnescapeString(cleanResult.ResponsePreview)
		cleanFindings[i] = &cleanResult
	}
	scan.Results = append(scan.Results, cleanFindings...)

	// Update bypass modes
	if !strings.Contains(scan.BypassModes, mode) {
		if scan.BypassModes != "" {
			scan.BypassModes += ","
		}
		scan.BypassModes += mode
	}

	// Write updated data
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create JSON file: %v", err)
	}
	defer file.Close()

	GB403Logger.Success().Msgf("Results saved to %s\n\n", outputFile)

	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func PrintResultsFromJSON(jsonFile, targetURL, bypassModule string) error {
	file, err := os.Open(jsonFile)
	if err != nil {
		return fmt.Errorf("failed to open JSON file: %v", err)
	}
	defer file.Close()

	var data JSONData
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		return fmt.Errorf("failed to decode JSON: %v", err)
	}

	var matchedResults []*Result
	queryModules := strings.Split(bypassModule, ",")

	for _, scan := range data.Scans {
		if scan.URL == targetURL {
			storedModules := strings.Split(scan.BypassModes, ",")

			// Check if any query module exists in stored modules
			for _, qm := range queryModules {
				for _, sm := range storedModules {
					if strings.TrimSpace(qm) == strings.TrimSpace(sm) {
						matchedResults = append(matchedResults, scan.Results...)
						break
					}
				}
			}
		}
	}

	if len(matchedResults) == 0 {
		return fmt.Errorf("no results found for %s with module %s", targetURL, bypassModule)
	}

	// Original sorting logic
	sort.Slice(matchedResults, func(i, j int) bool {
		if matchedResults[i].StatusCode != matchedResults[j].StatusCode {
			return matchedResults[i].StatusCode < matchedResults[j].StatusCode
		}
		return matchedResults[i].BypassModule < matchedResults[j].BypassModule
	})

	PrintResultsTable(targetURL, matchedResults)
	return nil
}
