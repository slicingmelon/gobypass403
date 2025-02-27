package scanner

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"database/sql"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/bytesutil"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pterm/pterm"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

// to optimize
// https://turriate.com/articles/making-sqlite-faster-in-go

var (
	fileLock      sync.RWMutex
	db            *sql.DB
	dbInitOnce    sync.Once
	resultsDBFile atomic.Value
	stmtPool      chan *sql.Stmt
)

func InitDB(dbPath string, workers int) error {
	var initErr error
	dbInitOnce.Do(func() {
		// Enhanced connection string with shared cache and WAL
		db, initErr = sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_sync=NORMAL&_busy_timeout=5000&cache=shared&mode=rwc")
		if initErr != nil {
			return
		}

		// Create tables and indexes first
		_, initErr = db.Exec(`
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                bypass_module TEXT NOT NULL,
                curl_cmd TEXT,
                response_headers TEXT,
                response_body_preview TEXT,
                status_code INTEGER,
                content_type TEXT,
                content_length INTEGER,
                response_body_bytes INTEGER,
                title TEXT,
                server_info TEXT,
                redirect_url TEXT,
                response_time INTEGER,
                debug_token TEXT,
                scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_target_url ON scan_results(target_url);
            CREATE INDEX IF NOT EXISTS idx_bypass_module ON scan_results(bypass_module);
            CREATE INDEX IF NOT EXISTS idx_status_code ON scan_results(status_code);
        `)
		if initErr != nil {
			return
		}

		// Initialize statement pool
		maxConns := workers + (workers / 10)
		stmtPool = make(chan *sql.Stmt, maxConns)

		// Pre-prepare statements for the pool
		for i := 0; i < maxConns; i++ {
			stmt, err := db.Prepare(`
                INSERT INTO scan_results (
                    target_url, bypass_module, curl_cmd, response_headers,
                    response_body_preview, status_code, content_type, content_length,
                    response_body_bytes, title, server_info, redirect_url,
                    response_time, debug_token
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `)
			if err != nil {
				initErr = fmt.Errorf("failed to prepare statement: %v", err)
				return
			}
			stmtPool <- stmt
		}
	})
	return initErr
}

type Result struct {
	TargetURL           string
	BypassModule        string
	CurlCMD             string
	ResponseHeaders     string
	ResponseBodyPreview string
	StatusCode          int
	ContentType         string
	ContentLength       int64
	ResponseBodyBytes   int
	Title               string
	ServerInfo          string
	RedirectURL         string
	ResponseTime        int64
	DebugToken          string
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
			bytesutil.Itoa(result.StatusCode),
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

func PrintResultsTableFromDB(targetURL, bypassModule string) error {
	GB403Logger.Verbose().Msgf("Querying results from database for: %s\n", targetURL)

	queryModules := strings.Split(bypassModule, ",")
	placeholders := strings.Repeat("?,", len(queryModules))
	placeholders = placeholders[:len(placeholders)-1] // Remove trailing comma

	query := fmt.Sprintf(`
        SELECT 
            target_url, bypass_module, curl_cmd, response_headers,
            response_body_preview, status_code, content_type, content_length,
            response_body_bytes, title, server_info, redirect_url,
            response_time, debug_token
        FROM scan_results
        WHERE target_url = ? AND bypass_module IN (%s)
        ORDER BY status_code ASC, bypass_module ASC
    `, placeholders)

	// Prepare query arguments
	args := make([]any, len(queryModules)+1)
	args[0] = targetURL
	for i, module := range queryModules {
		args[i+1] = module
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		return fmt.Errorf("database query error: %v", err)
	}
	defer rows.Close()

	var matchedResults []*Result
	for rows.Next() {
		var result Result
		err := rows.Scan(
			&result.TargetURL,
			&result.BypassModule,
			&result.CurlCMD,
			&result.ResponseHeaders,
			&result.ResponseBodyPreview,
			&result.StatusCode,
			&result.ContentType,
			&result.ContentLength,
			&result.ResponseBodyBytes,
			&result.Title,
			&result.ServerInfo,
			&result.RedirectURL,
			&result.ResponseTime,
			&result.DebugToken,
		)
		if err != nil {
			return fmt.Errorf("failed to scan row: %v", err)
		}
		matchedResults = append(matchedResults, &result)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("row iteration error: %v", err)
	}

	if len(matchedResults) == 0 {
		return fmt.Errorf("no results found for %s (modules: %s)", targetURL, bypassModule)
	}

	PrintResultsTable(targetURL, matchedResults)
	return nil
}

func AppendResultsToDB(results []*Result) error {
	if len(results) == 0 {
		return nil
	}

	// Get prepared statement from pool
	stmt := <-stmtPool
	defer func() {
		stmtPool <- stmt // Return statement to pool
	}()

	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	// Use the prepared statement from pool
	txStmt := tx.Stmt(stmt)
	defer txStmt.Close()

	for _, result := range results {
		_, err := txStmt.Exec(
			result.TargetURL,
			result.BypassModule,
			result.CurlCMD,
			result.ResponseHeaders,
			result.ResponseBodyPreview,
			result.StatusCode,
			result.ContentType,
			result.ContentLength,
			result.ResponseBodyBytes,
			result.Title,
			result.ServerInfo,
			result.RedirectURL,
			result.ResponseTime,
			result.DebugToken,
		)
		if err != nil {
			return fmt.Errorf("failed to insert result: %v", err)
		}
	}

	return tx.Commit()
}

func CleanupFindingsDB() {
	if db != nil {
		// Drain and close all prepared statements in the pool
		close(stmtPool)
		for stmt := range stmtPool {
			stmt.Close()
		}
		db.Close()
	}
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
