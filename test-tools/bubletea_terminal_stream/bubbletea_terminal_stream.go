// main.go
package main

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"
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

type row struct {
	module  string
	status  string
	rawCurl string
	oneCurl string
}

type target struct {
	name     string
	module   string
	done     int
	total    int
	complete bool
	err      string
}

/* ---------- messages from scanner ---------- */

type ProgressMsg struct {
	Target   string
	Module   string
	Done     int
	Total    int
	Complete bool
	Err      string
}

type ResultMsg struct {
	Target string
	Row    row
}

/* ---------- TUI model ---------- */

type viewKind int

const (
	viewDashboard viewKind = iota
	viewDetails
)

type model struct {
	view viewKind

	// dashboard
	targets []target
	selDash int

	// details
	activeTarget string
	rowsByTarget map[string][]row
	selDetail    int

	// layout
	width int

	// details copy hitbox
	copyStart int
	copyEnd   int

	// status
	statusMsg   string
	statusUntil time.Time
}

/* ---------- styles ---------- */

var (
	title   = lipgloss.NewStyle().Bold(true)
	muted   = lipgloss.NewStyle().Faint(true)
	th      = lipgloss.NewStyle().Bold(true)
	selRow  = lipgloss.NewStyle().Background(lipgloss.Color("236"))
	ok      = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	fail    = lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Bold(true)
	copyLbl = "[Copy]"

	// dashboard column widths
	colSite   = 30
	colModule = 16
	colProg   = 16
	colState  = 10

	// details column widths
	dColModule = 14
	dColStatus = 7

	headerLinesDash = 3
	headerLinesDet  = 3
	borderRune      = "─"
)

/* ---------- model impl ---------- */

func newModel(targetNames []string) *model {
	ts := make([]target, 0, len(targetNames))
	for _, n := range targetNames {
		ts = append(ts, target{name: n, module: "-", total: 0, done: 0, complete: false})
	}
	return &model{
		view:         viewDashboard,
		targets:      ts,
		rowsByTarget: make(map[string][]row),
	}
}

func (m *model) Init() tea.Cmd { return tea.EnterAltScreen }

/* ---------- update ---------- */

type tickMsg struct{}

func tick() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width

	case ProgressMsg:
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
			m.targets = append(m.targets, target{
				name: msg.Target, module: msg.Module, done: msg.Done, total: msg.Total, complete: msg.Complete, err: msg.Err,
			})
		}

	case ResultMsg:
		r := msg.Row
		if r.oneCurl == "" {
			r.oneCurl = oneLine(r.rawCurl)
		}
		m.rowsByTarget[msg.Target] = append(m.rowsByTarget[msg.Target], r)

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
				m.activeTarget = m.targets[m.selDash].name
				m.selDetail = 0
				m.view = viewDetails
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
					m.activeTarget = m.targets[m.selDash].name
					m.selDetail = 0
					m.view = viewDetails
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

func (m *model) View() string {
	switch m.view {
	case viewDashboard:
		return m.viewDashboard()
	case viewDetails:
		return m.viewDetails()
	default:
		return ""
	}
}

func (m *model) viewDashboard() string {
	var b strings.Builder
	b.WriteString(title.Render("Scan Dashboard") + "\n")
	b.WriteString(muted.Render("↑/↓ move   Enter open details   b/backspace back   q quit") + "\n\n")

	// header
	b.WriteString(
		th.Render(padRight("Site", colSite)) + "  " +
			th.Render(padRight("Module", colModule)) + "  " +
			th.Render(padRight("Progress", colProg)) + "  " +
			th.Render(padRight("State", colState)) + "\n")
	b.WriteString(strings.Repeat(borderRune, clamp(m.width, 0, 200)) + "\n")

	// rows
	for i, t := range m.targets {
		state := "-"
		if t.err != "" {
			state = fail.Render("error")
		} else if t.complete {
			state = ok.Render("done")
		} else {
			state = "running"
		}
		prog := fmt.Sprintf("%3d/%-3d (%3d%%)", t.done, t.total, percent(t.done, t.total))
		line := padRight(t.name, colSite) + "  " +
			padRight(t.module, colModule) + "  " +
			padRight(prog, colProg) + "  " +
			padRight(state, colState)
		if i == m.selDash {
			line = selRow.Render(line)
		}
		b.WriteString(line + "\n")
	}
	if m.statusMsg != "" {
		b.WriteString("\n" + muted.Render(m.statusMsg) + "\n")
	}
	return b.String()
}

func (m *model) viewDetails() string {
	var b strings.Builder
	header := fmt.Sprintf("Results for %s", m.activeTarget)
	b.WriteString(title.Render(header) + "\n")
	b.WriteString(muted.Render("↑/↓ move   c copy row   A copy all   b/backspace back   q quit") + "\n\n")

	rows := m.rowsByTarget[m.activeTarget]
	avail := m.width
	if avail < 40 {
		avail = 40
	}

	totalPad := 2 + 2 + 2 // spaces between columns
	copyW := len(copyLbl)
	curlAvail := avail - dColModule - dColStatus - totalPad - copyW
	if curlAvail < 10 {
		curlAvail = 10
	}

	// header
	b.WriteString(
		th.Render(padRight("Module", dColModule)) + "  " +
			th.Render(padRight("Curl CMD", curlAvail)) + "  " +
			th.Render(padRight("Status", dColStatus)) + "\n")
	b.WriteString(strings.Repeat(borderRune, clamp(m.width, 0, 200)) + "\n")

	// compute copy hitbox (relative to full line)
	m.copyStart = dColModule + 2 + curlAvail + 1 // space before [Copy]
	m.copyEnd = m.copyStart + len(copyLbl)

	for i, r := range rows {
		curlPreview := r.oneCurl
		if len(curlPreview) > curlAvail {
			curlPreview = curlPreview[:curlAvail-1] + "…"
		}
		line := padRight(r.module, dColModule) + "  " +
			padRight(curlPreview, curlAvail) + " " + ok.Render(copyLbl) + "  " +
			padRight(r.status, dColStatus)
		if i == m.selDetail {
			line = selRow.Render(line)
		}
		b.WriteString(line + "\n")
	}

	if m.statusMsg != "" {
		b.WriteString("\n" + muted.Render(m.statusMsg) + "\n")
	}
	return b.String()
}

/* ---------- actions ---------- */

func (m *model) copyOneWithMsg(i int, viaCopyButton bool) {
	rows := m.rowsByTarget[m.activeTarget]
	if i < 0 || i >= len(rows) {
		return
	}
	if err := copyToClipboard(rows[i].oneCurl); err != nil {
		m.statusMsg = "copy failed: " + err.Error()
	} else {
		if viaCopyButton {
			m.statusMsg = "✅ copied via [Copy]"
		} else {
			m.statusMsg = "✅ copied"
		}
	}
	m.statusUntil = time.Now().Add(2 * time.Second)
}

func (m *model) copyAllCurrent() {
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
		m.statusMsg = "✅ copied ALL"
	}
	m.statusUntil = time.Now().Add(2 * time.Second)
}

/* ---------- demo: simulate a scanner that streams updates ---------- */

func simulateScanner(p *tea.Program, target string, total int) {
	modules := []string{"dumb_check", "case_substitution", "end_paths"}
	curMod := modules[rand.Intn(len(modules))]

	for i := 0; i <= total; i++ {
		// progress
		p.Send(ProgressMsg{
			Target: target, Module: curMod, Done: i, Total: total, Complete: i == total,
		})

		// sometimes change module label mid-run
		if i == total/2 {
			curMod = modules[rand.Intn(len(modules))]
		}

		// occasionally add a result row
		if i%max(1, total/5) == 0 && i > 0 {
			curl := fmt.Sprintf("curl.exe -skgi --path-as-is \\\n'https://%s/path/%d' \\\n -H 'Accept: text/html'", strings.TrimPrefix(target, "https://"), i)
			p.Send(ResultMsg{
				Target: target,
				Row: row{
					module:  curMod,
					status:  []string{"200", "302", "403"}[rand.Intn(3)],
					rawCurl: curl,
				},
			})
		}
		time.Sleep(time.Duration(120+rand.Intn(120)) * time.Millisecond)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

/* ---------- main ---------- */

func main() {
	rand.Seed(time.Now().UnixNano())

	targets := []string{
		"https://demo.dev/site-a",
		"https://demo.dev/site-b",
	}

	m := newModel(targets)
	prog := tea.NewProgram(m, tea.WithMouseCellMotion())

	// simulate scanning in background; in your tool, send from real scanner
	go func() {
		for _, t := range targets {
			go simulateScanner(prog, t, 24+rand.Intn(18))
		}
	}()

	if err := prog.Start(); err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
}
