package scanner

import (
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

var (
	db         *sql.DB
	dbInitOnce sync.Once
	stmtPool   chan *sql.Stmt
)

func InitDB(dbPath string, workers int) error {
	var initErr error
	dbInitOnce.Do(func() {
		// Enhanced connection string with shared cache and WAL
		db, initErr = sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_sync=NORMAL&_busy_timeout=10000&_locking_mode=NORMAL&cache=shared&mode=rwc")
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
		maxConns := workers + (workers / 3)
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

var terminalStringBuilderPool = sync.Pool{
	New: func() any {
		return &strings.Builder{}
	},
}

func getTerminalStringBuilder() *strings.Builder {
	return terminalStringBuilderPool.Get().(*strings.Builder)
}

func putTerminalStringBuilder(sb *strings.Builder) {
	sb.Reset()
	terminalStringBuilderPool.Put(sb)
}

func PrintResultsTableFromDB(targetURL, bypassModule string) error {
	queryModules := strings.Split(bypassModule, ",")
	placeholders := strings.Repeat("?,", len(queryModules))
	placeholders = placeholders[:len(placeholders)-1] // Remove trailing comma

	// Optimized query - only fetch columns needed for display
	query := fmt.Sprintf(`
        SELECT 
            bypass_module, curl_cmd, status_code, 
            response_body_bytes, content_type, title, server_info
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

	// Build table rows from query results
	var tableData pterm.TableData
	tableData = append(tableData, getTableHeader())

	rowCount := 0
	for rows.Next() {
		rowCount++
		var module, curlCmd, contentType, title, serverInfo string
		var statusCode, responseBodyBytes int

		err := rows.Scan(
			&module,
			&curlCmd,
			&statusCode,
			&responseBodyBytes,
			&contentType,
			&title,
			&serverInfo,
		)
		if err != nil {
			return fmt.Errorf("failed to scan row: %v", err)
		}

		tableData = append(tableData, []string{
			module,
			curlCmd,
			bytesutil.Itoa(statusCode),
			formatBytes(int64(responseBodyBytes)),
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

	// Display header
	pterm.DefaultHeader.WithBackgroundStyle(pterm.NewStyle(pterm.BgGreen)).
		Println("Results for " + targetURL)

	// Configure the table
	table := pterm.DefaultTable.
		WithHasHeader().
		WithBoxed().
		WithData(tableData)

	tableStr, err := table.Srender()
	if err != nil {
		return fmt.Errorf("failed to render table: %v", err)
	}
	// Get a preallocated buffer from the pool
	sb := getTerminalStringBuilder()
	defer putTerminalStringBuilder(sb)

	sb.WriteString(tableStr)

	fmt.Print(sb.String())
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
