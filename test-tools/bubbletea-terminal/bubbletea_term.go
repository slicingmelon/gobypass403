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

// ---------- utils ----------

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
	// Best UX: cross-platform Go clipboard
	if err := clipboard.Init(); err == nil {
		clipboard.Write(clipboard.FmtText, []byte(s))
		return nil
	}
	// Fallbacks
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
	// Last ditch: OSC52 (if terminal supports it)
	b64 := base64.StdEncoding.EncodeToString([]byte(s))
	_, err := fmt.Printf("\x1b]52;c;%s\x07", b64)
	return err
}

// ---------- TUI ----------

type row struct {
	raw     string // original (possibly multiline)
	oneline string // one-liner (copy target)
}

type model struct {
	rows        []row
	cursor      int
	width       int
	status      string
	statusUntil time.Time
}

func newModel(raws []string) model {
	rs := make([]row, 0, len(raws))
	for _, r := range raws {
		rs = append(rs, row{raw: r, oneline: oneLine(r)})
	}
	return model{rows: rs}
}

func (m model) Init() tea.Cmd { return tea.EnterAltScreen }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.rows)-1 {
				m.cursor++
			}
		case "enter", "c":
			m.copyOne(m.cursor)
		case "A":
			m.copyAll()
		}
	case tea.MouseMsg:
		// Copy when clicking on a row (simple: any left click on the line)
		if msg.Button == tea.MouseButtonLeft && msg.Action == tea.MouseActionPress {
			line := msg.Y - 3 // adjust for header
			if line >= 0 && line < len(m.rows) {
				m.cursor = line
				m.copyOne(line)
			}
		}
	case tickMsg:
		if time.Now().After(m.statusUntil) {
			m.status = ""
		} else {
			return m, tick()
		}
	}
	return m, tick()
}

type tickMsg struct{}

func tick() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(time.Time) tea.Msg { return tickMsg{} })
}

var (
	titleStyle   = lipgloss.NewStyle().Bold(true)
	headerStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("87"))
	selectedRow  = lipgloss.NewStyle().Background(lipgloss.Color("236"))
	copyBtnStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	faint        = lipgloss.NewStyle().Faint(true)
)

func (m model) View() string {
	if len(m.rows) == 0 {
		return "No data\n"
	}

	var b strings.Builder
	b.WriteString(titleStyle.Render("CURL Results") + "\n")
	b.WriteString(headerStyle.Render("↑/↓ move   Enter/c copy row   A copy all   q quit") + "\n\n")

	for i, r := range m.rows {
		line := fmt.Sprintf("%2d. %s  %s",
			i+1,
			preview(r.oneline, max(20, m.width-20)),
			copyBtnStyle.Render("[Copy]"),
		)
		if i == m.cursor {
			line = selectedRow.Render(line)
		}
		b.WriteString(line + "\n")
	}

	if m.status != "" {
		b.WriteString("\n" + faint.Render(m.status) + "\n")
	}
	return b.String()
}

func (m *model) copyOne(i int) {
	if i < 0 || i >= len(m.rows) {
		return
	}
	if err := copyToClipboard(m.rows[i].oneline); err != nil {
		m.status = "copy failed: " + err.Error()
	} else {
		m.status = "✅ copied row " + fmt.Sprint(i+1) + " to clipboard"
	}
	m.statusUntil = time.Now().Add(2 * time.Second)
}

func (m *model) copyAll() {
	var items []string
	for _, r := range m.rows {
		items = append(items, r.oneline)
	}
	if err := copyToClipboard(strings.Join(items, "\n")); err != nil {
		m.status = "copy-all failed: " + err.Error()
	} else {
		m.status = "✅ copied ALL to clipboard"
	}
	m.statusUntil = time.Now().Add(2 * time.Second)
}

func preview(s string, width int) string {
	if len(s) <= width {
		return s
	}
	if width <= 1 {
		return "…"
	}
	return s[:width-1] + "…"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ----- demo -----
func main() {
	// Replace these with the multi-line curl blocks you already generate per row
	raws := []string{
		"curl.exe -skgi --path-as-is \\\n'https://demo.dev/healthz/test/admin/bypass' \\\n -H 'Accept: text/html' \\\n --data-binary $'aaaaaaaa'",
		"curl.exe -skgi --path-as-is \\\n'https://demo.dev/healthz/test/admin/bypass/aaa.mp4/..;/'\n -H 'Accept: text/html'",
	}

	if err := tea.NewProgram(newModel(raws), tea.WithMouseCellMotion()).Start(); err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
}
