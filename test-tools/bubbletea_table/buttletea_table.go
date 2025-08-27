// main.go
package main

import (
	"encoding/base64"
	"fmt"
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

/* ---------- utils ---------- */

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
	// OSC-52 fallback
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

/* ---------- data ---------- */

type row struct {
	module  string
	status  string
	rawCurl string
	oneCurl string
}

type model struct {
	rows        []row
	sel         int
	width       int
	statusMsg   string
	statusUntil time.Time
	// layout
	colModule int // width
	colStatus int // width
	// hitbox for [Copy] (computed each View)
	copyStart int
	copyEnd   int
}

func newModel(rows []row) model {
	for i := range rows {
		rows[i].oneCurl = oneLine(rows[i].rawCurl)
	}
	return model{
		rows:      rows,
		colModule: 14,
		colStatus: 7,
	}
}

func (m *model) Init() tea.Cmd { return tea.EnterAltScreen }

/* ---------- styles ---------- */

var (
	titleStyle  = lipgloss.NewStyle().Bold(true)
	headerStyle = lipgloss.NewStyle().Faint(true)
	thStyle     = lipgloss.NewStyle().Bold(true)
	selStyle    = lipgloss.NewStyle().Background(lipgloss.Color("236"))
	copyStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	faint       = lipgloss.NewStyle().Faint(true)
	border      = "─"
	copyLabel   = "[Copy]"
	paddingCols = 2
	headerLines = 3
)

/* ---------- update ---------- */

type tickMsg struct{}

func tick() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			m.sel = clamp(m.sel-1, 0, len(m.rows)-1)
		case "down", "j":
			m.sel = clamp(m.sel+1, 0, len(m.rows)-1)
		case "c":
			m.copyOneWithMsg(m.sel, false)
		case "A":
			m.copyAll()
		}
	case tea.MouseMsg:
		if msg.Button == tea.MouseButtonLeft && msg.Action == tea.MouseActionPress {
			rowIdx := msg.Y - headerLines - 2 // title+help + header + border
			if rowIdx >= 0 && rowIdx < len(m.rows) {
				m.sel = rowIdx

				// did we click on the [Copy] label?
				onCopy := msg.X >= m.copyStart && msg.X < m.copyEnd

				if onCopy || copyOnRowClick {
					m.copyOneWithMsg(rowIdx, onCopy)
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
	if len(m.rows) == 0 {
		return "No results\n"
	}

	var b strings.Builder
	b.WriteString(titleStyle.Render("Results") + "\n")
	b.WriteString(headerStyle.Render("↑/↓ move   c copy row   A copy all   q quit") + "\n\n")

	// compute layout
	totalPad := paddingCols * 3 // between 3 columns
	copyW := len(copyLabel)
	curlAvail := m.width - m.colModule - m.colStatus - totalPad - copyW
	if curlAvail < 10 {
		curlAvail = 10
	}
	// header
	b.WriteString(
		thStyle.Render(padRight("Module", m.colModule)) + strings.Repeat(" ", paddingCols) +
			thStyle.Render(padRight("Curl CMD", curlAvail)) + strings.Repeat(" ", paddingCols) +
			thStyle.Render(padRight("Status", m.colStatus)) + "\n")
	b.WriteString(strings.Repeat(border, clamp(m.width, 0, 200)) + "\n")

	// figure out where [Copy] starts horizontally for hit-testing
	m.copyStart = m.colModule + paddingCols + curlAvail + 1 // +1 space before label
	m.copyEnd = m.copyStart + copyW

	// rows
	for i, r := range m.rows {
		curlPreview := r.oneCurl
		if len(curlPreview) > curlAvail {
			curlPreview = curlPreview[:curlAvail-1] + "…"
		}
		line := padRight(r.module, m.colModule) + strings.Repeat(" ", paddingCols) +
			padRight(curlPreview, curlAvail) + " " + copyStyle.Render(copyLabel) + strings.Repeat(" ", paddingCols) +
			padRight(r.status, m.colStatus)

		if i == m.sel {
			line = selStyle.Render(line)
		}
		b.WriteString(line + "\n")
	}

	if m.statusMsg != "" {
		b.WriteString("\n" + faint.Render(m.statusMsg) + "\n")
	}
	return b.String()
}

/* ---------- actions ---------- */

func (m *model) copyOne(i int) {
	if i < 0 || i >= len(m.rows) {
		return
	}
	if err := copyToClipboard(m.rows[i].oneCurl); err != nil {
		m.statusMsg = "copy failed: " + err.Error()
	} else {
		m.statusMsg = "✅ copied: " + m.rows[i].module
	}
	m.statusUntil = time.Now().Add(2 * time.Second)
}

func (m *model) copyAll() {
	var all []string
	for _, r := range m.rows {
		all = append(all, r.oneCurl)
	}
	if err := copyToClipboard(strings.Join(all, "\n")); err != nil {
		m.statusMsg = "copy-all failed: " + err.Error()
	} else {
		m.statusMsg = "✅ copied ALL"
	}
	m.statusUntil = time.Now().Add(2 * time.Second)
}

func (m *model) copyOneWithMsg(i int, viaCopyButton bool) {
	if i < 0 || i >= len(m.rows) {
		return
	}
	if err := copyToClipboard(m.rows[i].oneCurl); err != nil {
		m.statusMsg = "copy failed: " + err.Error()
	} else {
		if viaCopyButton {
			m.statusMsg = "✅ copied via [Copy]: " + m.rows[i].module
		} else {
			m.statusMsg = "✅ copied via 'c': " + m.rows[i].module
		}
	}
	m.statusUntil = time.Now().Add(2 * time.Second)
}

/* ---------- demo ---------- */

func main() {
	// demo data — wire this to your DB results
	rows := []row{
		{
			module:  "end_paths",
			status:  "200",
			rawCurl: "curl.exe -skgi --path-as-is \\\n'https://demo.dev/healthz/test/admin/bypass' \\\n -H 'Accept: text/html' \\\n --data-binary $'aaaaaaaa'",
		},
		{
			module:  "end_paths",
			status:  "302",
			rawCurl: "curl.exe -skgi --path-as-is \\\n'https://demo.dev/healthz/test/admin/bypass/aaa.mp4/..;/'\n -H 'Accept: text/html'",
		},
	}

	m := newModel(rows)
	if err := tea.NewProgram(&m, tea.WithMouseCellMotion()).Start(); err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
}
