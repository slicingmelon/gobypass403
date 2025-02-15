package scanner

import (
	"fmt"
	"os"
	"path/filepath"
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

type Result struct {
	TargetURL           string `json:"TargetURL"`
	BypassModule        string `json:"BypassModule"`
	CurlCMD             string `json:"CurlCMD"`
	ResponseHeaders     string `json:"ResponseHeaders"`
	ResponseBodyPreview string `json:"ResponseBodyPreview"`
	StatusCode          int    `json:"StatusCode"`
	ContentType         string `json:"ContentType"`
	ContentLength       int64  `json:"ContentLength"`
	ResponseBodyBytes   int    `json:"ResponseBodyBytes"`
	Title               string `json:"Title"`
	ServerInfo          string `json:"ServerInfo"`
	RedirectURL         string `json:"RedirectURL"`
	ResponseTime        int64  `json:"ResponseTime"`
	DebugToken          string `json:"DebugToken"`
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
			FormatBytes(int64(result.ResponseBodyBytes)),
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

// var jsonAPI = sonic.ConfigStd

var jsonAPI = sonic.Config{
	UseNumber:   true,
	EscapeHTML:  false, // This is key - prevents HTML escaping
	SortMapKeys: false,
}.Froze()

func PrintResultsFromJSON(jsonFile, targetURL, bypassModule string) error {
	GB403Logger.Warning().
		Msgf("Reading results from JSON for %s", jsonFile)

	fileData, err := os.ReadFile(jsonFile)
	if err != nil {
		return fmt.Errorf("failed to open JSON file: %v", err)
	}

	var data JSONData
	if err := sonic.ConfigFastest.Unmarshal(fileData, &data); err != nil {
		return fmt.Errorf("failed to decode JSON: %v", err)
	}

	// Add debug logging for scans found
	for _, scan := range data.Scans {
		GB403Logger.Warning().
			Msgf("Found scan in JSON for %s", scan.URL)
	}

	var matchedResults []*Result
	queryModules := strings.Split(bypassModule, ",")

	for _, scan := range data.Scans {
		if scan.URL == targetURL {
			// Special case for "all" module
			if bypassModule == "all" {
				matchedResults = append(matchedResults, scan.Results...)
				continue
			}

			// Match specific modules
			for _, qm := range queryModules {
				if strings.Contains(scan.BypassModes, strings.TrimSpace(qm)) {
					matchedResults = append(matchedResults, scan.Results...)
					break
				}
			}
		}
	}

	if len(matchedResults) == 0 {
		return fmt.Errorf("no results found for %s with module %s", targetURL, bypassModule)
	}

	// Sort results
	sort.Slice(matchedResults, func(i, j int) bool {
		if matchedResults[i].StatusCode != matchedResults[j].StatusCode {
			return matchedResults[i].StatusCode < matchedResults[j].StatusCode
		}
		return string(matchedResults[i].BypassModule) < string(matchedResults[j].BypassModule)
	})

	PrintResultsTable(targetURL, matchedResults)
	return nil
}

func AppendResultsToJSON(outputFile, url, mode string, findings []*Result) error {
	// Skip if no findings, but only for non-dumb_check modules
	if len(findings) == 0 && mode != "dumb_check" {
		GB403Logger.Warning().
			Msgf("Skipping JSON write for %s - no findings to write", url)
		return nil
	}

	fileLock.Lock()
	defer fileLock.Unlock()

	var data JSONData
	fileData, err := os.ReadFile(outputFile)
	if err == nil {
		if err := jsonAPI.Unmarshal(fileData, &data); err != nil {
			return fmt.Errorf("failed to parse existing JSON: %v", err)
		}
	}

	// Find or create scan result
	var scan *ScanResult
	for i := range data.Scans {
		if data.Scans[i].URL == url {
			scan = &data.Scans[i]
			break
		}
	}

	if scan == nil {
		data.Scans = append(data.Scans, ScanResult{
			URL:         url,
			BypassModes: mode,
			ResultsPath: filepath.Dir(outputFile),
			Results:     make([]*Result, 0, len(findings)),
		})
		scan = &data.Scans[len(data.Scans)-1]
	}

	// Append findings
	for _, result := range findings {
		if result != nil {
			cleanResult := *result
			// ResponsePreview is already in raw form, no need to unescape
			scan.Results = append(scan.Results, &cleanResult)
		}
	}

	// Update bypass modes
	if !strings.Contains(scan.BypassModes, mode) {
		if scan.BypassModes != "" {
			scan.BypassModes += ","
		}
		scan.BypassModes += mode
	}

	// Use Sonic's fastest config with pre-allocated buffer
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create JSON file: %v", err)
	}
	defer file.Close()

	// Use MarshalIndent with 4 spaces indentation
	encoded, err := jsonAPI.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode JSON: %v", err)
	}

	_, err = file.Write(encoded)
	return err
}
