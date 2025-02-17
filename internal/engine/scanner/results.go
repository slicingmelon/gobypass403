package scanner

import (
	"bufio"
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

func PrintResultsTableFromJson(jsonFile, targetURL, bypassModule string) error {
	GB403Logger.Warning().Msgf("Reading results from JSON for %s", jsonFile)

	fileData, err := os.ReadFile(jsonFile)
	if err != nil {
		return fmt.Errorf("failed to read JSON file: %v", err)
	}

	var data JSONData
	if err := jsonAPI.Unmarshal(fileData, &data); err != nil {
		return fmt.Errorf("failed to decode JSON: %v", err)
	}

	urlData, exists := data[targetURL]
	if !exists {
		return fmt.Errorf("no results found for %s", targetURL)
	}

	var matchedResults []*Result
	queryModules := strings.Split(bypassModule, ",")

	if bypassModule == "all" {
		// Collect all results for the URL
		for _, results := range urlData {
			matchedResults = append(matchedResults, results...)
		}
	} else {
		// Collect specific modules
		for _, qm := range queryModules {
			qm = strings.TrimSpace(qm)
			if results, exists := urlData[qm]; exists {
				matchedResults = append(matchedResults, results...)
			}
		}
	}

	if len(matchedResults) == 0 {
		return fmt.Errorf("no matching results for %s with module %s", targetURL, bypassModule)
	}

	// Sort results (existing sorting logic)
	sort.Slice(matchedResults, func(i, j int) bool {
		if matchedResults[i].StatusCode != matchedResults[j].StatusCode {
			return matchedResults[i].StatusCode < matchedResults[j].StatusCode
		}
		return matchedResults[i].BypassModule < matchedResults[j].BypassModule
	})

	PrintResultsTable(targetURL, matchedResults)
	return nil
}

func PrintResultsTableFromJsonL(jsonFile, targetURL, bypassModule string) error {
	GB403Logger.Info().Msgf("Parsing results from: %s", jsonFile)

	file, err := os.Open(jsonFile)
	if err != nil {
		return fmt.Errorf("file open error: %v", err)
	}
	defer file.Close()

	var matchedResults []*Result
	queryModules := strings.Split(bypassModule, ",")
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		var result Result
		if err := jsonAPI.Unmarshal(scanner.Bytes(), &result); err != nil {
			GB403Logger.Debug().Msgf("Invalid JSON line: %v", err)
			continue
		}

		// Strict matching criteria
		if result.TargetURL == targetURL && slices.Contains(queryModules, result.BypassModule) {
			matchedResults = append(matchedResults, &result)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("file read error: %v", err)
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

func AppendResultsToJson(outputFile, url, mode string, findings []*Result) error {
	if len(findings) == 0 && mode != "dumb_check" {
		GB403Logger.Debug().Msgf("Skipping JSON write for %s - no findings", url)
		return nil
	}

	fileLock.Lock()
	defer fileLock.Unlock()

	// Load existing data
	var data JSONData
	fileData, err := os.ReadFile(outputFile)
	if err == nil {
		if err := jsonAPI.Unmarshal(fileData, &data); err != nil {
			return fmt.Errorf("failed to parse JSON: %v", err)
		}
	} else {
		data = make(JSONData)
	}

	// Initialize URL entry if needed
	if _, exists := data[url]; !exists {
		data[url] = make(map[string][]*Result)
	}

	// Append results under the bypass mode
	data[url][mode] = append(data[url][mode], findings...)

	// Write back to file
	encoded, err := jsonAPI.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode JSON: %v", err)
	}

	return os.WriteFile(outputFile, encoded, 0644)
}

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

	for _, result := range findings {
		line, err := jsonAPI.Marshal(result)
		if err != nil {
			GB403Logger.Error().Msgf("Failed to marshal result: %v\n", err)
			continue
		}
		if _, err = file.Write(append(line, '\n')); err != nil {
			GB403Logger.Error().Msgf("Failed to write JSONL entry: %v\n", err)
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
