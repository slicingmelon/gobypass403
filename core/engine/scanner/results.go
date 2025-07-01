/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package scanner

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"database/sql"

	_ "github.com/mattn/go-sqlite3"
	"github.com/pterm/pterm"
	"github.com/slicingmelon/go-bytesutil/bytesutil"
)

// to optimize
// https://turriate.com/articles/making-sqlite-faster-in-go
// https://use.expensify.com/blog/scaling-sqlite-to-4m-qps-on-a-single-server
// https://github.com/mattn/go-sqlite3/issues/1022#issuecomment-1067353980
// https://github.com/zzxgzgz/SQLite_Multithreading_Go/blob/5eebf73f8b5b9ab09981b37456c72349983be2d1/worker_pool/woker_pool.go#L97-L107

var (
	db         *sql.DB
	dbInitOnce sync.Once
	stmtPool   chan *sql.Stmt
	dbPath     string
)

func InitDB(dbFilePath string, workers int) error {
	var initErr error
	dbInitOnce.Do(func() {
		dbPath = dbFilePath

		// Enhanced connection string with WAL mode and immediate transactions
		db, initErr = sql.Open("sqlite3", "file:"+dbPath+"?_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=10000&_txlock=immediate&mode=rwc")
		if initErr != nil {
			return
		}

		// Set connection limits
		db.SetMaxOpenConns(1) // Only one writer connection
		db.SetMaxIdleConns(1)
		db.SetConnMaxLifetime(0)

		// Create tables and indexes first
		_, initErr = db.Exec(`
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                bypass_module TEXT NOT NULL,
                status_code INTEGER,
                content_length INTEGER,
                response_headers TEXT,
                response_body_preview TEXT,
                response_body_bytes INTEGER,
                title TEXT,
                server_info TEXT,
                redirect_url TEXT,
                curl_cmd TEXT,
                debug_token TEXT,
                response_time INTEGER,
                content_type TEXT,
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
		stmtPool = make(chan *sql.Stmt, 1) // Only need one prepared statement since we're using a single connection

		// Pre-prepare the single statement with correct SQL syntax
		stmt, err := db.Prepare(`
            INSERT INTO scan_results (
                target_url, bypass_module, status_code, content_length,
                response_headers, response_body_preview, response_body_bytes,
                title, server_info, redirect_url, curl_cmd, debug_token, 
                response_time, content_type
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
		if err != nil {
			initErr = fmt.Errorf("failed to prepare statement: %v", err)
			return
		}
		stmtPool <- stmt
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

func PrintResultsTableFromDB(targetURL, bypassModule string) error {
	// Extract dbPath from existing connection
	roDb, err := sql.Open("sqlite3", "file:"+dbPath+"?_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=10000&cache=shared&mode=ro")
	if err != nil {
		return fmt.Errorf("failed to open read-only database: %v", err)
	}
	defer roDb.Close()

	// Configure read-only connection for optimal performance
	roDb.SetMaxOpenConns(10)
	roDb.SetMaxIdleConns(5)

	queryModules := strings.Split(bypassModule, ",")
	placeholders := strings.Repeat("?,", len(queryModules))
	placeholders = placeholders[:len(placeholders)-1] // Remove trailing comma

	query := fmt.Sprintf(`
        SELECT 
            bypass_module, curl_cmd, status_code, 
            response_body_bytes, content_length, content_type, title, server_info,
            response_body_preview
        FROM scan_results
        WHERE target_url = ? AND bypass_module IN (%s)
        ORDER BY status_code ASC, bypass_module ASC, 
                 CASE WHEN content_length > 0 THEN content_length ELSE response_body_bytes END ASC
    `, placeholders)

	// Prepare query arguments
	args := make([]any, len(queryModules)+1)
	args[0] = targetURL
	for i, module := range queryModules {
		args[i+1] = module
	}

	// Prepare the statement with the actual query
	stmt, err := roDb.Prepare(query)
	if err != nil {
		return fmt.Errorf("failed to prepare query: %v", err)
	}
	defer stmt.Close()

	// Execute the query
	rows, err := stmt.Query(args...)
	if err != nil {
		return fmt.Errorf("database query error: %v", err)
	}
	defer rows.Close()

	// New code: Group results by module -> status code -> content length
	type ResultGroup struct {
		rows [][]string
		size int
	}

	tableData := pterm.TableData{getTableHeader()}
	rowCount := 0

	var currentModule, currentStatus string
	var currentLength int64 = -9999 // Reverted: Identifier for the current sub-group (content/body length)
	var currentGroup ResultGroup

	for rows.Next() {
		var module, curlCmd, contentType, title, serverInfo string
		var responseBodyPreview string // Still needed for potential future logic, but not primary grouper now
		var statusCode, responseBodyBytes int
		var contentLength sql.NullInt64

		err := rows.Scan(&module, &curlCmd, &statusCode, &responseBodyBytes,
			&contentLength, &contentType, &title, &serverInfo,
			&responseBodyPreview)
		if err != nil {
			return fmt.Errorf("failed to scan row: %v", err)
		}

		// Determine effective content length (lengthToDisplay)
		var lengthToDisplay int64
		if contentLength.Valid && contentLength.Int64 > 0 {
			lengthToDisplay = contentLength.Int64
		} else {
			lengthToDisplay = int64(responseBodyBytes)
		}

		statusStr := bytesutil.Itoa(statusCode)
		lengthStr := formatBytes(lengthToDisplay)

		// Check if we need to start a new group (major: module/status, or minor: lengthToDisplay)
		if module != currentModule || statusStr != currentStatus || lengthToDisplay != currentLength {
			// If it's a major group change (module or status differs)
			if currentModule != "" && (module != currentModule || statusStr != currentStatus) {
				if currentGroup.size > 0 { // Flush previous group's items
					tableData = append(tableData, currentGroup.rows...)

					// Add separator with dots matching previous module length
					dotCount := max(len(currentModule), 4)
					// Ensure tableData[0] (header) exists before trying to get its length for separator
					if len(tableData) > 0 && len(tableData[0]) > 0 {
						separator := make([]string, len(tableData[0]))
						separator[0] = strings.Repeat(".", dotCount)
						tableData = append(tableData, separator)
					}
				}
			} else if currentGroup.size > 0 { // Else, it's only a sub-group change (same module, same status, different length)
				// Just flush the previous group's items, no separator
				tableData = append(tableData, currentGroup.rows...)
			}

			// Start new group
			currentModule = module
			currentStatus = statusStr
			currentLength = lengthToDisplay // Reverted: Update to the new sub-group key (content/body length)
			currentGroup = ResultGroup{
				rows: make([][]string, 0, 5), // Max 5 items per sub-group
				size: 0,
			}
		}

		// Skip if we already have 5 results for this (module, status, length)
		if currentGroup.size >= 5 {
			continue
		}

		// Add to current group
		currentGroup.rows = append(currentGroup.rows, []string{
			module,
			LimitStringWithSuffix(curlCmd, 115),
			statusStr,
			lengthStr, // Reverted: Use the original length string for display
			formatContentType(contentType),
			LimitStringWithSuffix(formatValue(title), 14),
			LimitStringWithSuffix(formatValue(serverInfo), 14),
		})
		currentGroup.size++
		rowCount++
	}

	// Don't forget to add the last group
	if currentGroup.size > 0 {
		tableData = append(tableData, currentGroup.rows...)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("row iteration error: %v", err)
	}

	if rowCount == 0 {
		return fmt.Errorf("no results found for %s (modules: %s)", targetURL, bypassModule)
	}

	// Display header directly to avoid an allocation
	pterm.DefaultHeader.WithBackgroundStyle(pterm.NewStyle(pterm.BgGreen)).
		Println("Results summary for " + targetURL)

	// Configure the table
	table := pterm.DefaultTable.
		WithHasHeader().
		WithBoxed().
		WithData(tableData)

	// Render table directly into a string (avoiding the extra allocation)
	tableStr, err := table.Srender()
	if err != nil {
		return fmt.Errorf("failed to render table: %v", err)
	}

	// Print the rendered table directly
	fmt.Println(tableStr)

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

	// Start immediate transaction
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	// Use the prepared statement from pool
	txStmt := tx.Stmt(stmt)
	defer txStmt.Close()

	// Batch insert all results in a single transaction
	for _, result := range results {
		_, err := txStmt.Exec(
			result.TargetURL,
			result.BypassModule,
			result.StatusCode,
			result.ContentLength,
			result.ResponseHeaders,
			result.ResponseBodyPreview,
			result.ResponseBodyBytes,
			result.Title,
			result.ServerInfo,
			result.RedirectURL,
			result.CurlCMD,
			result.DebugToken,
			result.ResponseTime,
			result.ContentType,
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

func LimitStringWithSuffix(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	return s[:maxLen-4] + "[..]"
}

func LimitStringwithPreffixAndSuffix(s string, maxLen int) string {
	if maxLen < 6 {
		maxLen = 6
	}
	if len(s) <= maxLen {
		return s
	}
	n := (maxLen / 2) - 2
	return s[:n] + "[..]" + s[len(s)-n:]
}
