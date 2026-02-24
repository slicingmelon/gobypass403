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
                content_type TEXT,
                response_headers TEXT,
                response_body_preview TEXT,
                response_body_bytes INTEGER,
                title TEXT,
                server_info TEXT,
                redirect_url TEXT,
                curl_cmd TEXT,
                debug_token TEXT,
                response_time INTEGER,
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
                target_url, bypass_module, status_code, content_length, content_type,
                response_headers, response_body_preview, response_body_bytes,
                title, server_info, redirect_url, curl_cmd, debug_token, 
                response_time
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

		currentGroup.rows = append(currentGroup.rows, []string{
			module,
			curlCmd,
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
		return nil
	}

	// Display header directly to avoid an allocation
	pterm.DefaultHeader.WithBackgroundStyle(pterm.NewStyle(pterm.BgGreen)).
		Println("Results summary for " + targetURL)

	// Configure the table
	table := pterm.DefaultTable.
		WithHasHeader().
		WithBoxed().
		WithRowSeparator("-").
		WithHeaderRowSeparator("-").
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
			result.ContentType,
			result.ResponseHeaders,
			result.ResponseBodyPreview,
			result.ResponseBodyBytes,
			result.Title,
			result.ServerInfo,
			result.RedirectURL,
			result.CurlCMD,
			result.DebugToken,
			result.ResponseTime,
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

// SplitCurlPocIntoMultiLines intelligently splits curl commands into multiple lines
// based on OS conventions and smart URL breaking points
func SplitCurlPocIntoMultiLines(curlCmd string, maxLen int) string {
	if len(curlCmd) <= maxLen {
		return curlCmd
	}

	// Detect OS for line continuation
	isWindows := strings.Contains(curlCmd, "curl.exe")
	var lineContinuation string
	if isWindows {
		lineContinuation = " `"
	} else {
		lineContinuation = " \\"
	}

	// Parse curl command into tokens
	tokens := parseCurlTokens(curlCmd)
	if len(tokens) == 0 {
		return curlCmd
	}

	// Pre-process tokens: split any long tokens (except the last one which is likely the URL)
	processedTokens := make([]string, 0, len(tokens)*2) // Pre-allocate with some extra space

	for i, token := range tokens {
		isLastToken := i == len(tokens)-1

		if len(token) > maxLen && !isLastToken {
			// Split long non-URL tokens into chunks
			chunks := splitLongToken(token, maxLen)
			processedTokens = append(processedTokens, chunks...)
		} else {
			processedTokens = append(processedTokens, token)
		}
	}

	var lines []string
	var currentLine strings.Builder

	// Start with the curl command
	currentLine.WriteString(processedTokens[0])

	for i := 1; i < len(processedTokens); i++ {
		token := processedTokens[i]
		isLastToken := i == len(processedTokens)-1

		// Check if adding this token would exceed maxLen
		testLine := currentLine.String() + " " + token

		if len(testLine) <= maxLen {
			// Token fits on current line
			currentLine.WriteString(" ")
			currentLine.WriteString(token)
		} else {
			// Token doesn't fit, need to handle it
			if isLastToken && isURLToken(token) && len(token) > maxLen {
				// Handle long URLs (last token) by smart splitting at path boundaries
				urlLines := splitLongURL(token, maxLen, lineContinuation)

				// Add current line with continuation
				lines = append(lines, currentLine.String()+lineContinuation)

				// Add all URL lines except the last
				for j := 0; j < len(urlLines)-1; j++ {
					lines = append(lines, "  "+urlLines[j]+lineContinuation)
				}

				// Start new line with the last URL part
				currentLine.Reset()
				currentLine.WriteString("  ")
				currentLine.WriteString(urlLines[len(urlLines)-1])
			} else {
				// Regular token that doesn't fit - start new line
				lines = append(lines, currentLine.String()+lineContinuation)
				currentLine.Reset()
				currentLine.WriteString("  ")
				currentLine.WriteString(token)
			}
		}
	}

	// Add the final line (no continuation needed)
	if currentLine.Len() > 0 {
		lines = append(lines, currentLine.String())
	}

	return strings.Join(lines, "\n")
}

// parseCurlTokens parses a curl command into individual tokens, preserving quoted strings
func parseCurlTokens(curlCmd string) []string {
	var tokens []string
	var current strings.Builder
	var inQuotes bool
	var quoteChar rune

	runes := []rune(curlCmd)

	for i := 0; i < len(runes); i++ {
		r := runes[i]

		if !inQuotes {
			switch r {
			case '\'', '"':
				inQuotes = true
				quoteChar = r
				current.WriteRune(r)
			case ' ', '\t':
				if current.Len() > 0 {
					tokens = append(tokens, current.String())
					current.Reset()
				}
			default:
				current.WriteRune(r)
			}
		} else {
			current.WriteRune(r)
			if r == quoteChar {
				// Check if it's escaped
				if i == 0 || runes[i-1] != '\\' {
					inQuotes = false
				}
			}
		}
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}

// isURLToken checks if a token is likely a URL (more reliable than length-based check)
func isURLToken(token string) bool {
	// Check for quoted URLs
	if (strings.HasPrefix(token, "'http") && strings.HasSuffix(token, "'")) ||
		(strings.HasPrefix(token, "\"http") && strings.HasSuffix(token, "\"")) {
		return true
	}

	// Check for unquoted URLs
	return strings.HasPrefix(token, "http://") || strings.HasPrefix(token, "https://")
}

// splitLongToken splits a long non-URL token into smaller chunks
func splitLongToken(token string, maxLen int) []string {
	if len(token) <= maxLen {
		return []string{token}
	}

	var chunks []string

	// Handle quoted strings specially
	if (strings.HasPrefix(token, "'") && strings.HasSuffix(token, "'")) ||
		(strings.HasPrefix(token, "\"") && strings.HasSuffix(token, "\"")) {

		quote := string(token[0])
		content := token[1 : len(token)-1] // Remove quotes

		// Split the content into chunks
		chunkSize := maxLen - 2 // Account for quotes
		if chunkSize < 1 {
			chunkSize = maxLen - 1 // Fallback
		}

		for len(content) > 0 {
			if len(content) <= chunkSize {
				chunks = append(chunks, quote+content+quote)
				break
			}

			chunk := content[:chunkSize]
			chunks = append(chunks, quote+chunk+quote)
			content = content[chunkSize:]
		}
	} else {
		// Handle unquoted strings - simple chunking
		for len(token) > 0 {
			if len(token) <= maxLen {
				chunks = append(chunks, token)
				break
			}

			chunk := token[:maxLen]
			chunks = append(chunks, chunk)
			token = token[maxLen:]
		}
	}

	return chunks
}

// splitLongURL intelligently splits a long URL at path boundaries
func splitLongURL(url string, maxLen int, lineContinuation string) []string {
	// Remove quotes to work with the actual URL
	originalQuotes := ""
	actualURL := url
	if strings.HasPrefix(url, "'") && strings.HasSuffix(url, "'") {
		originalQuotes = "'"
		actualURL = url[1 : len(url)-1]
	} else if strings.HasPrefix(url, "\"") && strings.HasSuffix(url, "\"") {
		originalQuotes = "\""
		actualURL = url[1 : len(url)-1]
	}

	var lines []string
	remaining := actualURL

	for len(remaining) > 0 {
		if len(remaining) <= maxLen-len(originalQuotes)*2 {
			// Last piece fits
			if originalQuotes != "" {
				lines = append(lines, originalQuotes+remaining+originalQuotes)
			} else {
				lines = append(lines, remaining)
			}
			break
		}

		// Find the best split point within maxLen
		splitPoint := findBestURLSplitPoint(remaining, maxLen-len(originalQuotes)*2-len(lineContinuation))

		if splitPoint == -1 {
			// No good split point found, force split at maxLen
			splitPoint = maxLen - len(originalQuotes)*2 - len(lineContinuation)
		}

		piece := remaining[:splitPoint]
		if originalQuotes != "" {
			lines = append(lines, originalQuotes+piece+originalQuotes)
		} else {
			lines = append(lines, piece)
		}

		remaining = remaining[splitPoint:]
	}

	return lines
}

// findBestURLSplitPoint finds the best place to split a URL within maxLen
func findBestURLSplitPoint(url string, maxLen int) int {
	if len(url) <= maxLen {
		return len(url)
	}

	// Look for path separators within the limit, starting from the end
	for i := maxLen - 1; i >= maxLen/2; i-- {
		if i < len(url) && url[i] == '/' {
			return i
		}
	}

	// Look for query separators
	for i := maxLen - 1; i >= maxLen/2; i-- {
		if i < len(url) && (url[i] == '?' || url[i] == '&') {
			return i
		}
	}

	// Look for dots (domain separators)
	for i := maxLen - 1; i >= maxLen/2; i-- {
		if i < len(url) && url[i] == '.' {
			return i
		}
	}

	// No good split point found
	return -1
}
