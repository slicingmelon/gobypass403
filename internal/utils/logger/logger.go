package logger

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/jedib0t/go-pretty/v6/text"
)

///
// Enable debug/verbose if needed
// logger.DefaultLogger.EnableDebug()
// logger.DefaultLogger.EnableVerbose()

// // Basic logging
// logger.Info().Msgf("Starting scan...")
// logger.Error().Msgf("Error occurred: %v", err)

// // With metadata
// logger.Info().Str("module", "scanner").Msgf("Scan complete")

// // Debug with token
// logger.Debug().WithToken(debugToken).Msgf("Sending request...")

// // Colored output
// logger.PrintGreen("Success!")
//

var (
	DefaultLogger *Logger
)

func init() {
	DefaultLogger = &Logger{
		buffer:  &bytes.Buffer{},
		mu:      sync.Mutex{},
		verbose: false,
		debug:   false,
	}
}

type Logger struct {
	buffer  *bytes.Buffer
	mu      sync.Mutex
	verbose bool
	debug   bool
}

type Event struct {
	logger   *Logger
	message  string
	token    string // For debug messages
	metadata map[string]string
}

func (l *Logger) IsDebugEnabled() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.debug
}

func IsDebugEnabled() bool {
	return DefaultLogger.IsDebugEnabled()
}

// Core logging methods that return *Event
func Info() *Event {
	return DefaultLogger.newEvent()
}

func Error() *Event {
	return DefaultLogger.newEvent()
}

func Debug() *Event {
	if !DefaultLogger.debug {
		return nil
	}
	return DefaultLogger.newEvent()
}

func Verbose() *Event {
	if !DefaultLogger.verbose {
		return nil
	}
	return DefaultLogger.newEvent()
}

// Print methods for colored output
func PrintYellow(format string, args ...interface{}) {
	DefaultLogger.print(text.FgYellow, format, args...)
}

func PrintGreen(format string, args ...interface{}) {
	DefaultLogger.print(text.FgGreen, format, args...)
}

func PrintCyan(format string, args ...interface{}) {
	DefaultLogger.print(text.FgCyan, format, args...)
}

// Event methods
func (e *Event) Msgf(format string, args ...interface{}) {
	if e == nil {
		return
	}
	e.message = fmt.Sprintf(format, args...)
	e.logger.log(e)
}

func (e *Event) WithToken(token string) *Event {
	if e == nil {
		return nil
	}
	e.token = token
	return e
}

func (e *Event) Str(key, value string) *Event {
	if e == nil {
		return nil
	}
	if e.metadata == nil {
		e.metadata = make(map[string]string)
	}
	e.metadata[key] = value
	return e
}

// Logger methods
func (l *Logger) newEvent() *Event {
	return &Event{
		logger:   l,
		metadata: make(map[string]string),
	}
}

func (l *Logger) EnableVerbose() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.verbose = true
}

func (l *Logger) EnableDebug() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.debug = true
}

func (l *Logger) log(e *Event) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.buffer.Reset()

	// Add metadata if any
	var meta string
	for k, v := range e.metadata {
		meta += fmt.Sprintf(" %s=%s", text.Bold.Sprint(k), v)
	}

	// Format based on token presence (debug) or metadata
	if e.token != "" {
		header := text.Colors{text.BgHiRed, text.FgWhite, text.Bold}.Sprint("[DEBUG]")
		token := text.Colors{text.FgYellow, text.Bold}.Sprintf("[%s]", e.token)
		fmt.Printf("%s %s %s%s\n", header, token, e.message, meta)
	} else {
		fmt.Printf("%s%s\n", e.message, meta)
	}
}

func (l *Logger) print(color text.Color, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s\n", color.Sprint(msg))
}
