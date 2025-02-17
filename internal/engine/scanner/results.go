package scanner

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bytedance/sonic"
	"github.com/pterm/pterm"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

// Make fileLock package level
var (
	fileLock    sync.RWMutex
	resultsFile atomic.Value // Store the file path
	jsonStarted atomic.Bool
)

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

	// Add closing bracket if missing (in case of crash)
	if !bytes.HasSuffix(data, []byte("]")) {
		data = append(data, []byte("\n]")...)
	}

	var results []*Result
	if err := jsonAPI.Unmarshal(data, &results); err != nil {
		return fmt.Errorf("failed to parse JSON: %v", err)
	}

	var matchedResults []*Result
	queryModules := strings.Split(bypassModule, ",")

	// Filter results by URL and modules
	for _, result := range results {
		if result.TargetURL == targetURL && slices.Contains(queryModules, result.BypassModule) {
			matchedResults = append(matchedResults, result)
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

func AppendResultsToJsonL(outputFile string, findings []*Result) error {
	if len(findings) == 0 {
		return nil
	}

	fileLock.Lock()
	defer fileLock.Unlock()

	fileInfo, err := os.Stat(outputFile)
	fileExists := !os.IsNotExist(err)
	isEmpty := !fileExists || fileInfo.Size() == 0

	file, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("failed to open JSON file: %v", err)
	}
	defer file.Close()

	if isEmpty {
		file.WriteString("[")
	} else {
		if err := removeClosingBracket(file); err != nil {
			return fmt.Errorf("failed to prepare file: %v", err)
		}
		file.WriteString(",")
	}

	// Write new results
	for i, result := range findings {
		if i > 0 {
			file.WriteString(",")
		}

		data, err := jsonAPI.MarshalIndent(result, "  ", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal result: %v", err)
		}

		file.WriteString("\n  ")
		file.Write(data)
	}

	file.WriteString("\n]")
	return nil
}

func removeClosingBracket(file *os.File) error {
	// Seek to end minus 2 bytes (]\n)
	if _, err := file.Seek(-2, io.SeekEnd); err != nil {
		return err
	}

	pos, _ := file.Seek(0, io.SeekCurrent)
	return file.Truncate(pos)
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
