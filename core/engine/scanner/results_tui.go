/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package scanner

import (
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
	module  string
	status  string
	rawCurl string
	oneCurl string
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

type TUIResultMsg struct {
	Target string
	Row    TUIResultRow
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
	activeTarget string
	rowsByTarget map[string][]TUIResultRow
	selDetail    int

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

	// details column widths
	dColModule = 14
	dColStatus = 7

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
		view:         viewDashboard,
		targets:      ts,
		rowsByTarget: make(map[string][]TUIResultRow),
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

	case TUIResultMsg:
		r := msg.Row
		if r.oneCurl == "" {
			r.oneCurl = oneLine(r.rawCurl)
		}
		m.rowsByTarget[msg.Target] = append(m.rowsByTarget[msg.Target], r)

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
				m.selDetail = clamp(m.selDetail-1, 0, len(m.rowsByTarget[m.activeTarget])-1)
			case "down", "j":
				m.selDetail = clamp(m.selDetail+1, 0, len(m.rowsByTarget[m.activeTarget])-1)
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
						m.view = viewDetails
					}
				}
			}
		case viewDetails:
			if msg.Button == tea.MouseButtonLeft && msg.Action == tea.MouseActionPress {
				rowIdx := msg.Y - headerLinesDet - 2
				if rows := m.rowsByTarget[m.activeTarget]; rowIdx >= 0 && rowIdx < len(rows) {
					m.selDetail = rowIdx
					onCopy := msg.X >= m.copyStart && msg.X < m.copyEnd
					if onCopy || copyOnRowClick {
						m.copyOneWithMsg(rowIdx, onCopy)
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

	rows := m.rowsByTarget[m.activeTarget]
	avail := m.width
	if avail < 40 {
		avail = 40
	}

	totalPad := 2 + 2 + 2 // spaces between columns
	copyW := len(copyLblStyle)
	curlAvail := avail - dColModule - dColStatus - totalPad - copyW
	if curlAvail < 10 {
		curlAvail = 10
	}

	// header - using same format as original results table
	b.WriteString(
		thStyle.Render(padRight("Module", dColModule)) + "  " +
			thStyle.Render(padRight("Curl CMD", curlAvail)) + "  " +
			thStyle.Render(padRight("Status", dColStatus)) + "\n")
	b.WriteString(strings.Repeat(borderRune, clamp(m.width, 0, 200)) + "\n")

	// compute copy hitbox (relative to full line)
	m.copyStart = dColModule + 2 + curlAvail + 1 // space before [Copy]
	m.copyEnd = m.copyStart + len(copyLblStyle)

	for i, r := range rows {
		// Use the same multiline curl formatting as the original
		// formattedCurl := SplitCurlPocIntoMultiLines(r.rawCurl, curlAvail) // Available if needed later

		// For display, show first line only with ellipsis if multiline
		curlPreview := r.oneCurl
		if len(curlPreview) > curlAvail {
			curlPreview = curlPreview[:curlAvail-1] + "…"
		}

		line := padRight(r.module, dColModule) + "  " +
			padRight(curlPreview, curlAvail) + " " + okStyle.Render(copyLblStyle) + "  " +
			padRight(r.status, dColStatus)
		if i == m.selDetail {
			line = selRowStyle.Render(line)
		}
		b.WriteString(line + "\n")
	}

	if len(rows) == 0 {
		b.WriteString(mutedStyle.Render("No results found for this target.") + "\n")
	}

	if m.statusMsg != "" {
		b.WriteString("\n" + mutedStyle.Render(m.statusMsg) + "\n")
	}
	return b.String()
}

/* ---------- actions ---------- */

func (m *TUIModel) copyOneWithMsg(i int, viaCopyButton bool) {
	rows := m.rowsByTarget[m.activeTarget]
	if i < 0 || i >= len(rows) {
		return
	}
	if err := copyToClipboard(rows[i].oneCurl); err != nil {
		m.statusMsg = "copy failed: " + err.Error()
	} else {
		if viaCopyButton {
			m.statusMsg = "✅ copied via [Copy]: " + rows[i].module
		} else {
			m.statusMsg = "✅ copied via 'c': " + rows[i].module
		}
	}
	m.statusUntil = time.Now().Add(2 * time.Second)
}

func (m *TUIModel) copyAllCurrent() {
	rows := m.rowsByTarget[m.activeTarget]
	if len(rows) == 0 {
		return
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.oneCurl)
	}
	if err := copyToClipboard(strings.Join(out, "\n")); err != nil {
		m.statusMsg = "copy-all failed: " + err.Error()
	} else {
		m.statusMsg = fmt.Sprintf("✅ copied ALL (%d items)", len(rows))
	}
	m.statusUntil = time.Now().Add(2 * time.Second)
}

/* ---------- TUI Interface ---------- */

type TUIController struct {
	model      *TUIModel
	program    *tea.Program
	progressCh chan TUIProgressMsg
	resultCh   chan TUIResultMsg
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
		resultCh:   make(chan TUIResultMsg, 1000),
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
		case msg := <-c.resultCh:
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

func (c *TUIController) SendResult(target string, result *Result) {
	select {
	case c.resultCh <- TUIResultMsg{
		Target: target,
		Row: TUIResultRow{
			module:  result.BypassModule,
			status:  fmt.Sprintf("%d", result.StatusCode),
			rawCurl: result.CurlCMD,
			oneCurl: oneLine(result.CurlCMD),
		},
	}:
	default:
		// Channel full, skip this result
	}
}

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

func (c *TUIController) GetResultChannel() chan<- TUIResultMsg {
	return c.resultCh
}
