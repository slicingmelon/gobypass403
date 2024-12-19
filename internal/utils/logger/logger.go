package logger

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/jedib0t/go-pretty/v6/text"
)

type Logger struct {
	mu             sync.Mutex
	buffer         *bytes.Buffer
	stderr         io.Writer
	stdout         io.Writer
	verboseEnabled bool
	debugEnabled   bool
}

func NewLogger() *Logger {
	return &Logger{
		buffer: &bytes.Buffer{},
		stdout: os.Stdout, // For custom-colored messages
		stderr: os.Stderr, // For logs
	}
}

// Enable verbose mode
func (l *Logger) EnableVerbose() {
	l.verboseEnabled = true
}

// Enable debug mode
func (l *Logger) EnableDebug() {
	l.debugEnabled = true
}

func (l *Logger) IsDebugEnabled() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.debugEnabled
}

// Add the IsDebugEnabled method
func (l *Logger) IsVerboseEnabled() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.verboseEnabled
}

// Core log function
func (l *Logger) log(w io.Writer, color text.Color, prefix, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Format the message
	msg := fmt.Sprintf(format, args...)

	// Add color and prefix
	formattedMsg := color.Sprintf("%s%s", prefix, msg)

	// Write to the buffer and flush to the writer
	l.buffer.Reset()
	l.buffer.WriteString(formattedMsg)
	l.buffer.WriteRune('\n')
	w.Write(l.buffer.Bytes())
}

// Core print function (messages to stdout)
func (l *Logger) print(w io.Writer, color text.Color, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	msg := fmt.Sprintf(format, args...)
	formattedMsg := color.Sprintf("%s", msg)

	l.buffer.Reset()
	l.buffer.WriteString(formattedMsg)
	l.buffer.WriteRune('\n')
	w.Write(l.buffer.Bytes())
}

// LogInfo for status updates
func (l *Logger) LogInfo(format string, args ...interface{}) {
	l.log(l.stderr, text.FgWhite, "[INFO] ", format, args...)
}

// LogVerbose for verbose logs, only shown if verbose is enabled
func (l *Logger) LogVerbose(format string, args ...interface{}) {
	if !l.verboseEnabled {
		return
	}
	l.log(l.stderr, text.FgCyan, "[VERBOSE] ", format, args...)
}

// LogDebug for debug logs with custom metadata
func (l *Logger) LogDebug(requestID string, format string, args ...interface{}) {
	if !l.debugEnabled {
		return
	}
	// Include the requestID dynamically in the message
	fullFormat := fmt.Sprintf("[%s] %s", requestID, format)
	l.log(l.stderr, text.FgMagenta, "[DEBUG] ", fullFormat, args...)
}

// LogError for errors
func (l *Logger) LogError(format string, args ...interface{}) {
	l.log(l.stderr, text.FgRed, "[ERROR] ", format, args...)
}

// Custom-colored messages (stdout)
func (l *Logger) PrintYellow(format string, args ...interface{}) {
	l.print(l.stdout, text.FgYellow, format, args...)
}

func (l *Logger) PrintPurple(format string, args ...interface{}) {
	l.print(l.stdout, text.FgMagenta, format, args...)
}

func (l *Logger) PrintGreen(format string, args ...interface{}) {
	l.print(l.stdout, text.FgGreen, format, args...)
}

func (l *Logger) PrintOrange(format string, args ...interface{}) {
	l.print(l.stdout, text.FgHiYellow, format, args...)
}

func (l *Logger) PrintCyan(format string, args ...interface{}) {
	l.print(l.stdout, text.FgCyan, format, args...)
}

func (l *Logger) PrintTeal(format string, args ...interface{}) {
	l.print(l.stdout, text.FgHiCyan, format, args...)
}

// String color helpers
func (l *Logger) BlueString(format string, args ...interface{}) string {
	return text.FgBlue.Sprintf(format, args...)
}

func (l *Logger) YellowString(format string, args ...interface{}) string {
	return text.FgYellow.Sprintf(format, args...)
}

func (l *Logger) GreenString(format string, args ...interface{}) string {
	return text.FgGreen.Sprintf(format, args...)
}

func (l *Logger) PurpleString(format string, args ...interface{}) string {
	return text.FgMagenta.Sprintf(format, args...)
}

func (l *Logger) OrangeString(format string, args ...interface{}) string {
	return text.FgHiYellow.Sprintf(format, args...)
}

func (l *Logger) TealString(format string, args ...interface{}) string {
	return text.FgHiCyan.Sprintf(format, args...)
}

func (l *Logger) GrayString(format string, args ...interface{}) string {
	return text.FgHiBlack.Sprintf(format, args...)
}

func (l *Logger) PinkString(format string, args ...interface{}) string {
	return text.FgHiMagenta.Sprintf(format, args...)
}

// Optional: Change output for testing or redirection
func (l *Logger) SetOutput(stderr io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stderr = stderr
}
