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

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/bytesutil"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pterm/pterm"
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
		stmtPool = make(chan *sql.Stmt, 1) // Only need one prepared statement since we're using a single connection

		// Pre-prepare the single statement with correct SQL syntax
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

	// Updated query to include content_length column
	query := fmt.Sprintf(`
        SELECT 
            bypass_module, curl_cmd, status_code, 
            response_body_bytes, content_length, content_type, title, server_info
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

	// Build table rows from query results
	var tableData pterm.TableData
	tableData = append(tableData, getTableHeader())

	rowCount := 0
	for rows.Next() {
		rowCount++
		var module, curlCmd, contentType, title, serverInfo string
		var statusCode, responseBodyBytes int
		var contentLength sql.NullInt64 // Using NullInt64 to handle potential NULL values

		err := rows.Scan(
			&module,
			&curlCmd,
			&statusCode,
			&responseBodyBytes,
			&contentLength,
			&contentType,
			&title,
			&serverInfo,
		)
		if err != nil {
			return fmt.Errorf("failed to scan row: %v", err)
		}

		// Choose content length from Content-Length header when valid, otherwise use response body size
		var lengthToDisplay int64
		if contentLength.Valid && contentLength.Int64 >= 0 {
			lengthToDisplay = contentLength.Int64
		} else {
			lengthToDisplay = int64(responseBodyBytes)
		}

		tableData = append(tableData, []string{
			module,
			curlCmd,
			bytesutil.Itoa(statusCode),
			formatBytes(lengthToDisplay),
			formatContentType(contentType),
			formatValue(title),
			formatValue(serverInfo),
		})
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("row iteration error: %v", err)
	}

	if rowCount == 0 {
		return fmt.Errorf("no results found for %s (modules: %s)", targetURL, bypassModule)
	}

	// Display header directly to avoid an allocation
	pterm.DefaultHeader.WithBackgroundStyle(pterm.NewStyle(pterm.BgGreen)).
		Println("Results for " + targetURL)

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
