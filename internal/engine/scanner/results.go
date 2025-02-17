package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/sonic"
	"github.com/pterm/pterm"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

// Make fileLock package level
var fileLock sync.Mutex

type JSONData map[string]map[string][]*Result // url -> bypassMode -> results

var jsonAPI = sonic.Config{
	UseNumber:   true,
	EscapeHTML:  false, // This is key - prevents HTML escaping
	SortMapKeys: false,
}.Froze()

type Result struct {
	TargetURL           string `json:"target_url"`
	BypassModule        string `json:"bypass_module"`
	CurlCMD             string `json:"curl_cmd"`
	ResponseHeaders     string `json:"response_headers"`
	ResponseBodyPreview string `json:"response_body_preview"`
	StatusCode          int    `json:"status_code"`
	ContentType         string `json:"content_type"`
	ContentLength       int64  `json:"content_length"`
	ResponseBodyBytes   int    `json:"response_body_bytes"`
	Title               string `json:"title"`
	ServerInfo          string `json:"server_info"`
	RedirectURL         string `json:"redirect_url"`
	ResponseTime        int64  `json:"response_time"`
	DebugToken          string `json:"debug_token"`
}

// ScanResult represents results for a single URL scan
type ScanResult struct {
	URL         string    `json:"url"`
	BypassModes string    `json:"bypass_modes"`
	ResultsPath string    `json:"results_path"`
	Results     []*Result `json:"results"`
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
	// Create a copy of results to avoid races during sorting
	resultsCopy := make([]*Result, len(results))
	for i, r := range results {
		// Deep copy each result's fields
		resultsCopy[i] = &Result{
			BypassModule:      r.BypassModule,
			CurlCMD:           r.CurlCMD,
			StatusCode:        r.StatusCode,
			ResponseBodyBytes: r.ResponseBodyBytes,
			ContentType:       r.ContentType,
			Title:             r.Title,
			ServerInfo:        r.ServerInfo,
		}
	}

	// Sort the copy
	sort.Slice(resultsCopy, func(i, j int) bool {
		if resultsCopy[i].StatusCode != resultsCopy[j].StatusCode {
			return resultsCopy[i].StatusCode < resultsCopy[j].StatusCode
		}
		return string(resultsCopy[i].BypassModule) < string(resultsCopy[j].BypassModule)
	})

	// Convert to table rows using the copied data
	rows := make([][]string, len(resultsCopy))
	for i, result := range resultsCopy {
		rows[i] = []string{
			string(result.BypassModule),
			string(result.CurlCMD),
			strconv.Itoa(result.StatusCode),
			formatBytes(int64(result.ResponseBodyBytes)),
			formatContentType(string(result.ContentType)),
			formatValue(string(result.Title)),
			formatValue(string(result.ServerInfo)),
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

// PrintResultsTableFromJsonL prints the results table from findings.json instead of directly from the memory
func PrintResultsTableFromJsonL(jsonFile, targetURL, bypassModule string) error {
	GB403Logger.Verbose().Msgf("Parsing results from: %s\n", jsonFile)

	data, err := os.ReadFile(jsonFile)
	if err != nil {
		return fmt.Errorf("file read error: %v", err)
	}

	var matchedResults []*Result
	queryModules := strings.Split(bypassModule, ",")

	// Split by single newlines since each JSON object ends with one
	jsonObjects := bytes.Split(data, []byte("\n"))

	for _, jsonObj := range jsonObjects {
		if len(bytes.TrimSpace(jsonObj)) == 0 {
			continue
		}

		var result Result
		if err := jsonAPI.Unmarshal(jsonObj, &result); err != nil {
			GB403Logger.Debug().Msgf("Invalid JSON object: %v\n", err)
			continue
		}

		if result.TargetURL == targetURL && slices.Contains(queryModules, result.BypassModule) {
			matchedResults = append(matchedResults, &result)
		}
	}

	if len(matchedResults) == 0 {
		return fmt.Errorf("no results found for %s (modules: %s)", targetURL, bypassModule)
	}

	// Stable sort: status code asc -> module name asc
	sort.SliceStable(matchedResults, func(i, j int) bool {
		if matchedResults[i].StatusCode == matchedResults[j].StatusCode {
			return matchedResults[i].BypassModule < matchedResults[j].BypassModule
		}
		return matchedResults[i].StatusCode < matchedResults[j].StatusCode
	})

	PrintResultsTable(targetURL, matchedResults)
	return nil
}

// AppendResultsToJsonL appends the results to findings.json file, in JSONL format to optimize memory usage
func AppendResultsToJsonL(outputFile string, findings []*Result) error {
	if len(findings) == 0 {
		return nil
	}

	fileLock.Lock()
	defer fileLock.Unlock()

	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open JSONL file: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	for _, result := range findings {
		// Pretty print each JSON entry with 2-space indentation
		line, err := jsonAPI.MarshalIndent(result, "", "  ")
		if err != nil {
			GB403Logger.Error().Msgf("Failed to marshal result: %v", err)
			continue
		}

		// Write the pretty-printed JSON followed by a newline
		if _, err = writer.Write(line); err != nil {
			GB403Logger.Error().Msgf("Failed to write JSONL entry: %v", err)
			continue
		}
		if _, err = writer.Write([]byte("\n")); err != nil {
			GB403Logger.Error().Msgf("Failed to write newline: %v", err)
		}
	}

	return nil
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

func formatBytes(bytes int64) string {
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
