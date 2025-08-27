/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package scanner

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"golang.design/x/clipboard"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/slicingmelon/go-bytesutil/bytesutil"
)

const copyOnRowClick = false

/* ---------- clipboard & helpers ---------- */

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	var b strings.Builder
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(ln)
	}
	re := regexp.MustCompile(`[ \t]{2,}`)
	return re.ReplaceAllString(b.String(), " ")
}

// Helper function to format length from content length and response bytes
func formatLengthTUI(contentLength int64, responseBodyBytes int) string {
	if contentLength > 0 {
		return fmt.Sprintf("%d", contentLength)
	}
	if responseBodyBytes > 0 {
		return fmt.Sprintf("%d", responseBodyBytes)
	}
	return "[-]"
}

func copyToClipboard(s string) error {
	if err := clipboard.Init(); err == nil {
		clipboard.Write(clipboard.FmtText, []byte(s))
		return nil
	}
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("cmd", "/C", "clip")
		cmd.Stdin = strings.NewReader(s)
		return cmd.Run()
	case "darwin":
		cmd := exec.Command("pbcopy")
		cmd.Stdin = strings.NewReader(s)
		return cmd.Run()
	default:
		if _, err := exec.LookPath("wl-copy"); err == nil {
			cmd := exec.Command("wl-copy")
			cmd.Stdin = strings.NewReader(s)
			return cmd.Run()
		}
		if _, err := exec.LookPath("xclip"); err == nil {
			cmd := exec.Command("xclip", "-selection", "clipboard")
			cmd.Stdin = strings.NewReader(s)
			return cmd.Run()
		}
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(s))
	_, err := fmt.Printf("\x1b]52;c;%s\x07", b64)
	return err
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func percent(done, total int) int {
	if total <= 0 {
		return 0
	}
	p := (done * 100) / total
	if p < 0 {
		p = 0
	}
	if p > 100 {
		p = 100
	}
	return p
}

/* ---------- data types ---------- */

type TUIResultRow struct {
	module      string
	curlCmd     string
	status      string
	length      string
	contentType string
	title       string
	server      string
}

type TUITarget struct {
	name     string
	module   string
	done     int
	total    int
	complete bool
	err      string
}

/* ---------- messages from scanner ---------- */

type TUIProgressMsg struct {
	Target   string
	Module   string
	Done     int
	Total    int
	Complete bool
	Err      string
}

type TUIShutdownMsg struct{}

/* ---------- TUI model ---------- */

type viewKind int

const (
	viewDashboard viewKind = iota
	viewDetails
)

type TUIModel struct {
	view viewKind

	// dashboard
	targets []TUITarget
	selDash int

	// details
	activeTarget  string
	detailRows    []TUIResultRow
	selDetail     int
	detailsLoaded bool

	// layout
	width int

	// details copy hitbox
	copyStart int
	copyEnd   int

	// status
	statusMsg   string
	statusUntil time.Time

	// program control
	program *tea.Program
}

/* ---------- styles ---------- */

var (
	titleStyle   = lipgloss.NewStyle().Bold(true)
	mutedStyle   = lipgloss.NewStyle().Faint(true)
	thStyle      = lipgloss.NewStyle().Bold(true)
	selRowStyle  = lipgloss.NewStyle().Background(lipgloss.Color("236"))
	okStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	failStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Bold(true)
	copyLblStyle = "[Copy]"

	// dashboard column widths
	colSite   = 50
	colModule = 20
	colProg   = 20
	colState  = 12

	// details column widths (matching original table)
	dColModule = 14
	dColCurl   = 40 // Will be calculated dynamically
	dColStatus = 7
	dColLength = 8
	dColType   = 12
	dColTitle  = 14
	dColServer = 14

	headerLinesDash = 3
	headerLinesDet  = 3
	borderRune      = "─"
)

/* ---------- model impl ---------- */

func NewTUIModel(targetNames []string) *TUIModel {
	ts := make([]TUITarget, 0, len(targetNames))
	for _, n := range targetNames {
		ts = append(ts, TUITarget{name: n, module: "-", total: 0, done: 0, complete: false})
	}
	return &TUIModel{
		view:          viewDashboard,
		targets:       ts,
		detailRows:    make([]TUIResultRow, 0),
		detailsLoaded: false,
	}
}

func (m *TUIModel) Init() tea.Cmd {
	return tea.Batch(tea.EnterAltScreen, tick())
}

/* ---------- update ---------- */

type tickMsg struct{}

func tick() tea.Cmd {
	return tea.Tick(1000*time.Millisecond, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m *TUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width

	case TUIProgressMsg:
		// upsert target progress
		found := false
		for i := range m.targets {
			if m.targets[i].name == msg.Target {
				m.targets[i].module = msg.Module
				m.targets[i].done = msg.Done
				m.targets[i].total = msg.Total
				m.targets[i].complete = msg.Complete
				m.targets[i].err = msg.Err
				found = true
				break
			}
		}
		if !found {
			m.targets = append(m.targets, TUITarget{
				name: msg.Target, module: msg.Module, done: msg.Done, total: msg.Total, complete: msg.Complete, err: msg.Err,
			})
		}

	// TUIResultMsg removed - results now queried from database

	case TUIShutdownMsg:
		return m, tea.Quit

	case tea.KeyMsg:
		switch m.view {

		case viewDashboard:
			switch msg.String() {
			case "q", "esc", "ctrl+c":
				return m, tea.Quit
			case "up", "k":
				m.selDash = clamp(m.selDash-1, 0, len(m.targets)-1)
			case "down", "j":
				m.selDash = clamp(m.selDash+1, 0, len(m.targets)-1)
			case "enter":
				if len(m.targets) == 0 {
					break
				}
				selectedTarget := m.targets[m.selDash]
				if selectedTarget.complete {
					m.activeTarget = selectedTarget.name
					m.selDetail = 0
					m.detailsLoaded = false // Force reload from database
					m.view = viewDetails
				}
			}

		case viewDetails:
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "b", "backspace":
				m.view = viewDashboard
			case "up", "k":
				m.selDetail = clamp(m.selDetail-1, 0, len(m.detailRows)-1)
			case "down", "j":
				m.selDetail = clamp(m.selDetail+1, 0, len(m.detailRows)-1)
			case "c":
				m.copyOneWithMsg(m.selDetail, false)
			case "A":
				m.copyAllCurrent()
			}
		}

	case tea.MouseMsg:
		switch m.view {
		case viewDashboard:
			if msg.Button == tea.MouseButtonLeft && msg.Action == tea.MouseActionPress {
				rowIdx := msg.Y - headerLinesDash - 2
				if rowIdx >= 0 && rowIdx < len(m.targets) {
					m.selDash = rowIdx
					selectedTarget := m.targets[m.selDash]
					if selectedTarget.complete {
						m.activeTarget = selectedTarget.name
						m.selDetail = 0
						m.detailsLoaded = false // Force reload from database
						m.view = viewDetails
					}
				}
			}
		case viewDetails:
			if len(m.detailRows) > 0 {
				// Handle mouse actions
				if msg.Action == tea.MouseActionPress {
					// Handle wheel scrolling
					if msg.Button == tea.MouseButtonWheelUp {
						m.selDetail = clamp(m.selDetail-1, 0, len(m.detailRows)-1)
					} else if msg.Button == tea.MouseButtonWheelDown {
						m.selDetail = clamp(m.selDetail+1, 0, len(m.detailRows)-1)
					} else if msg.Button == tea.MouseButtonLeft {
						// Handle left click - find which result was clicked (accounting for multiline)
						clickY := msg.Y - headerLinesDet - 2
						if clickY >= 0 {
							resultIdx := m.findResultFromLineClick(clickY)
							if resultIdx >= 0 && resultIdx < len(m.detailRows) {
								m.selDetail = resultIdx
								onCopy := msg.X >= m.copyStart && msg.X < m.copyEnd
								if onCopy || copyOnRowClick {
									m.copyOneWithMsg(resultIdx, onCopy)
								}
							}
						}
					}
				}
			}
		}

	case tickMsg:
		if time.Now().After(m.statusUntil) {
			m.statusMsg = ""
		} else {
			return m, tick()
		}
	}
	return m, tick()
}

/* ---------- view ---------- */

func padRight(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if len(s) >= w {
		return s[:w]
	}
	return s + strings.Repeat(" ", w-len(s))
}

func (m *TUIModel) View() string {
	switch m.view {
	case viewDashboard:
		return m.viewDashboard()
	case viewDetails:
		return m.viewDetails()
	default:
		return ""
	}
}

func (m *TUIModel) viewDashboard() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("GoBypass403 - Scan Dashboard") + "\n")
	b.WriteString(mutedStyle.Render("↑/↓ move   Enter open details (completed targets only)   q quit") + "\n\n")

	// header
	b.WriteString(
		thStyle.Render(padRight("Target URL", colSite)) + "  " +
			thStyle.Render(padRight("Module", colModule)) + "  " +
			thStyle.Render(padRight("Progress", colProg)) + "  " +
			thStyle.Render(padRight("State", colState)) + "\n")
	b.WriteString(strings.Repeat(borderRune, clamp(m.width, 0, 200)) + "\n")

	// rows
	for i, t := range m.targets {
		state := "-"
		if t.err != "" {
			state = failStyle.Render("error")
		} else if t.complete {
			state = okStyle.Render("done")
		} else if t.total > 0 {
			state = "running"
		} else {
			state = "waiting"
		}

		prog := ""
		if t.total > 0 {
			prog = fmt.Sprintf("%3d/%-3d (%3d%%)", t.done, t.total, percent(t.done, t.total))
		} else {
			prog = "-"
		}

		line := padRight(t.name, colSite) + "  " +
			padRight(t.module, colModule) + "  " +
			padRight(prog, colProg) + "  " +
			padRight(state, colState)
		if i == m.selDash {
			line = selRowStyle.Render(line)
		}
		b.WriteString(line + "\n")
	}
	if m.statusMsg != "" {
		b.WriteString("\n" + mutedStyle.Render(m.statusMsg) + "\n")
	}
	return b.String()
}

func (m *TUIModel) viewDetails() string {
	var b strings.Builder
	header := fmt.Sprintf("Results for %s", m.activeTarget)
	b.WriteString(titleStyle.Render(header) + "\n")
	b.WriteString(mutedStyle.Render("↑/↓ move   c copy row   A copy all   b/backspace back   q quit") + "\n\n")

	// Load results from database if not already loaded
	if !m.detailsLoaded {
		err := m.loadResultsFromDB()
		if err != nil {
			b.WriteString(failStyle.Render("Error loading results: "+err.Error()) + "\n")
			return b.String()
		}
		m.detailsLoaded = true
	}

	if len(m.detailRows) == 0 {
		b.WriteString(mutedStyle.Render("No results found for this target.") + "\n")
		return b.String()
	}

	// Calculate column widths based on available space
	avail := m.width
	if avail < 80 {
		avail = 80
	}

	// Reserve space for separators (6 * 2 = 12)
	totalPadding := 12
	copyW := len(copyLblStyle)

	// Calculate curl column width (remaining space after fixed columns)
	fixedCols := dColModule + dColStatus + dColLength + dColType + dColTitle + dColServer + copyW
	curlAvail := avail - fixedCols - totalPadding
	if curlAvail < 30 {
		curlAvail = 30
	}

	// Header - matching original table format: Module, Curl CMD, Status, Length, Type, Title, Server
	b.WriteString(
		thStyle.Render(padRight("Module", dColModule)) + "  " +
			thStyle.Render(padRight("Curl CMD", curlAvail)) + "  " +
			thStyle.Render(padRight("Status", dColStatus)) + "  " +
			thStyle.Render(padRight("Length", dColLength)) + "  " +
			thStyle.Render(padRight("Type", dColType)) + "  " +
			thStyle.Render(padRight("Title", dColTitle)) + "  " +
			thStyle.Render(padRight("Server", dColServer)) + "\n")
	b.WriteString(strings.Repeat(borderRune, clamp(m.width, 0, 200)) + "\n")

	// Compute copy hitbox - position after curl column
	m.copyStart = dColModule + 2 + curlAvail + 1 // space before [Copy]
	m.copyEnd = m.copyStart + len(copyLblStyle)

	for i, r := range m.detailRows {
		// Display curl command as multiline (like original table)
		curlLines := strings.Split(r.curlCmd, "\n")

		// Build the row with multiline support
		for lineIdx, curlLine := range curlLines {
			var rowLine string

			if lineIdx == 0 {
				// First line: show all columns
				// Truncate curl line if too long
				curlDisplay := curlLine
				if len(curlDisplay) > curlAvail {
					curlDisplay = curlDisplay[:curlAvail-1] + "…"
				}

				rowLine = padRight(r.module, dColModule) + "  " +
					padRight(curlDisplay, curlAvail) + " " + okStyle.Render(copyLblStyle) + "  " +
					padRight(r.status, dColStatus) + "  " +
					padRight(r.length, dColLength) + "  " +
					padRight(r.contentType, dColType) + "  " +
					padRight(r.title, dColTitle) + "  " +
					padRight(r.server, dColServer)
			} else {
				// Continuation lines: only show curl command
				curlDisplay := curlLine
				if len(curlDisplay) > curlAvail {
					curlDisplay = curlDisplay[:curlAvail-1] + "…"
				}

				rowLine = padRight("", dColModule) + "  " +
					padRight(curlDisplay, curlAvail) + "  " +
					padRight("", dColStatus+len(copyLblStyle)+2) + "  " +
					padRight("", dColLength) + "  " +
					padRight("", dColType) + "  " +
					padRight("", dColTitle) + "  " +
					padRight("", dColServer)
			}

			if i == m.selDetail {
				rowLine = selRowStyle.Render(rowLine)
			}
			b.WriteString(rowLine + "\n")
		}
	}

	if m.statusMsg != "" {
		b.WriteString("\n" + mutedStyle.Render(m.statusMsg) + "\n")
	}
	return b.String()
}

/* ---------- helper functions ---------- */

func (m *TUIModel) findResultFromLineClick(clickY int) int {
	// Calculate which result was clicked based on line position
	// Each result can span multiple lines due to multiline curl commands
	currentLine := 0
	for i, r := range m.detailRows {
		curlLines := strings.Split(r.curlCmd, "\n")
		resultLines := len(curlLines)

		if clickY >= currentLine && clickY < currentLine+resultLines {
			return i
		}
		currentLine += resultLines
	}
	return -1 // Not found
}

/* ---------- actions ---------- */

func (m *TUIModel) copyOneWithMsg(i int, viaCopyButton bool) {
	if i < 0 || i >= len(m.detailRows) {
		return
	}
	if err := copyToClipboard(m.detailRows[i].curlCmd); err != nil {
		m.statusMsg = "copy failed: " + err.Error()
	} else {
		if viaCopyButton {
			m.statusMsg = "✅ copied via [Copy]: " + m.detailRows[i].module
		} else {
			m.statusMsg = "✅ copied via 'c': " + m.detailRows[i].module
		}
	}
	m.statusUntil = time.Now().Add(2 * time.Second)
}

func (m *TUIModel) copyAllCurrent() {
	if len(m.detailRows) == 0 {
		return
	}
	var out []string
	for _, r := range m.detailRows {
		out = append(out, r.curlCmd)
	}
	if err := copyToClipboard(strings.Join(out, "\n")); err != nil {
		m.statusMsg = "copy-all failed: " + err.Error()
	} else {
		m.statusMsg = fmt.Sprintf("✅ copied ALL (%d items)", len(m.detailRows))
	}
	m.statusUntil = time.Now().Add(2 * time.Second)
}

/* ---------- Database Query (matching original algorithm) ---------- */

func (m *TUIModel) loadResultsFromDB() error {
	// Clear existing results
	m.detailRows = m.detailRows[:0]

	// Get all modules that have been scanned for this target
	allModules := []string{
		"dumb_check", "case_substitution", "end_paths", "mid_paths",
		"http_methods", "headers", "ip_hosts", "ports", "proto_schemes", "url_encode",
	}

	// Query database using EXACT same approach as PrintResultsTableFromDB
	if err := m.queryAndProcessResults(m.activeTarget, allModules); err != nil {
		return fmt.Errorf("failed to query results: %v", err)
	}

	return nil
}

func (m *TUIModel) queryAndProcessResults(targetURL string, queryModules []string) error {
	// Open read-only database connection (same as original)
	roDb, err := sql.Open("sqlite3", "file:"+dbPath+"?_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=10000&cache=shared&mode=ro")
	if err != nil {
		return fmt.Errorf("failed to open read-only database: %v", err)
	}
	defer roDb.Close()

	// Configure read-only connection for optimal performance
	roDb.SetMaxOpenConns(10)
	roDb.SetMaxIdleConns(5)

	// Build query with placeholders (EXACT same as original)
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

	// Prepare query arguments (EXACT same as original)
	args := make([]any, len(queryModules)+1)
	args[0] = targetURL
	for i, module := range queryModules {
		args[i+1] = module
	}

	// Execute query
	stmt, err := roDb.Prepare(query)
	if err != nil {
		return fmt.Errorf("failed to prepare query: %v", err)
	}
	defer stmt.Close()

	rows, err := stmt.Query(args...)
	if err != nil {
		return fmt.Errorf("database query error: %v", err)
	}
	defer rows.Close()

	// Implement EXACT same grouping algorithm as original
	type ResultGroup struct {
		rows []TUIResultRow
		size int
	}

	var currentModule, currentStatus string
	var currentLength int64 = -9999 // Same as original
	var currentGroup ResultGroup

	for rows.Next() {
		var module, curlCmd, contentType, title, serverInfo string
		var responseBodyPreview string
		var statusCode, responseBodyBytes int
		var contentLength sql.NullInt64

		err := rows.Scan(&module, &curlCmd, &statusCode, &responseBodyBytes,
			&contentLength, &contentType, &title, &serverInfo,
			&responseBodyPreview)
		if err != nil {
			return fmt.Errorf("failed to scan row: %v", err)
		}

		// Determine effective content length (EXACT same logic as original)
		var lengthToDisplay int64
		if contentLength.Valid && contentLength.Int64 > 0 {
			lengthToDisplay = contentLength.Int64
		} else {
			lengthToDisplay = int64(responseBodyBytes)
		}

		statusStr := bytesutil.Itoa(statusCode)
		lengthStr := formatBytes(lengthToDisplay)

		// Check if we need to start a new group (EXACT same logic as original)
		if module != currentModule || statusStr != currentStatus || lengthToDisplay != currentLength {
			// If it's a major group change (module or status differs)
			if currentModule != "" && (module != currentModule || statusStr != currentStatus) {
				if currentGroup.size > 0 { // Flush previous group's items
					m.detailRows = append(m.detailRows, currentGroup.rows...)
				}
			} else if currentGroup.size > 0 { // Else, it's only a sub-group change (same module, same status, different length)
				// Just flush the previous group's items, no separator
				m.detailRows = append(m.detailRows, currentGroup.rows...)
			}

			// Start new group
			currentModule = module
			currentStatus = statusStr
			currentLength = lengthToDisplay
			currentGroup = ResultGroup{
				rows: make([]TUIResultRow, 0, 5), // Max 5 items per sub-group
				size: 0,
			}
		}

		// Skip if we already have 5 results for this (module, status, length) - EXACT same as original
		if currentGroup.size >= 5 {
			continue
		}

		// Add to current group - use multiline formatting for curl commands (EXACT same as original)
		formattedCurl := SplitCurlPocIntoMultiLines(curlCmd, 60)
		currentGroup.rows = append(currentGroup.rows, TUIResultRow{
			module:      module,
			curlCmd:     formattedCurl, // Store full multiline curl for copying
			status:      statusStr,
			length:      lengthStr,
			contentType: formatContentType(contentType),
			title:       LimitStringWithSuffix(formatValue(title), 14),
			server:      LimitStringWithSuffix(formatValue(serverInfo), 14),
		})
		currentGroup.size++
	}

	// Don't forget to add the last group (EXACT same as original)
	if currentGroup.size > 0 {
		m.detailRows = append(m.detailRows, currentGroup.rows...)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("row iteration error: %v", err)
	}

	return nil
}

/* ---------- TUI Interface ---------- */

type TUIController struct {
	model      *TUIModel
	program    *tea.Program
	progressCh chan TUIProgressMsg
	shutdownCh chan TUIShutdownMsg
}

func NewTUIController(targetURLs []string) *TUIController {
	model := NewTUIModel(targetURLs)
	program := tea.NewProgram(model, tea.WithMouseCellMotion())
	model.program = program

	controller := &TUIController{
		model:      model,
		program:    program,
		progressCh: make(chan TUIProgressMsg, 100),
		shutdownCh: make(chan TUIShutdownMsg, 1),
	}

	// Start message relay goroutines
	go controller.relayMessages()

	return controller
}

func (c *TUIController) relayMessages() {
	for {
		select {
		case msg := <-c.progressCh:
			c.program.Send(msg)
		case msg := <-c.shutdownCh:
			c.program.Send(msg)
			return
		}
	}
}

func (c *TUIController) SendProgress(target, module string, done, total int, complete bool, err string) {
	select {
	case c.progressCh <- TUIProgressMsg{
		Target:   target,
		Module:   module,
		Done:     done,
		Total:    total,
		Complete: complete,
		Err:      err,
	}:
	default:
		// Channel full, skip this update
	}
}

// SendResult method removed - results now queried from database when needed

func (c *TUIController) Start() error {
	return c.program.Start()
}

func (c *TUIController) Shutdown() {
	select {
	case c.shutdownCh <- TUIShutdownMsg{}:
	default:
	}
}

func (c *TUIController) GetProgressChannel() chan<- TUIProgressMsg {
	return c.progressCh
}

// GetResultChannel method removed - results now queried from database when needed
