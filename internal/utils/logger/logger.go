package logger

import (
	"os"
	"sync"

	"github.com/pterm/pterm"
)

type Logger struct {
	writer  *os.File // Changed from io.Writer to *os.File
	mu      sync.Mutex
	verbose bool
	debug   bool
}

var DefaultLogger *Logger

func init() {
	DefaultLogger = &Logger{
		writer:  os.Stdout, // Use os.Stdout instead of pterm.DefaultOutput
		verbose: false,
		debug:   false,
	}

	// Configure pterm styles
	pterm.Info.Prefix = pterm.Prefix{
		Text:  "INFO",
		Style: pterm.NewStyle(pterm.BgBlue, pterm.FgBlack),
	}

	pterm.Success.Prefix = pterm.Prefix{
		Text:  "SUCCESS",
		Style: pterm.NewStyle(pterm.BgGreen, pterm.FgBlack),
	}

	pterm.Warning.Prefix = pterm.Prefix{
		Text:  "WARNING",
		Style: pterm.NewStyle(pterm.BgYellow, pterm.FgBlack),
	}

	pterm.Error.Prefix = pterm.Prefix{
		Text:  "ERROR",
		Style: pterm.NewStyle(pterm.BgRed, pterm.FgBlack),
	}
}

type Event struct {
	logger       *Logger
	printer      pterm.PrefixPrinter // Remove pointer
	bypassModule string
	debugToken   string
	metadata     map[string]string
}

func (l *Logger) newEvent(printer pterm.PrefixPrinter) *Event { // Remove pointer from parameter
	return &Event{
		logger:   l,
		printer:  printer,
		metadata: make(map[string]string),
	}
}

// Core logging methods
func Info() *Event {
	return DefaultLogger.newEvent(pterm.Info)
}

func Success() *Event {
	return DefaultLogger.newEvent(pterm.Success)
}

func Error() *Event {
	return DefaultLogger.newEvent(pterm.Error)
}

func Warning() *Event {
	return DefaultLogger.newEvent(pterm.Warning)
}

func Debug() *Event {
	if !DefaultLogger.debug {
		return nil
	}
	return DefaultLogger.newEvent(pterm.Debug)
}

func Verbose() *Event {
	if !DefaultLogger.verbose {
		return nil
	}
	return DefaultLogger.newEvent(pterm.Info) // Use Info style for verbose
}

func (e *Event) Msgf(format string, args ...interface{}) {
	if e == nil {
		return
	}

	e.logger.mu.Lock()
	defer e.logger.mu.Unlock()

	// Build metadata string
	var meta string
	for k, v := range e.metadata {
		meta += " " + pterm.Bold.Sprint(k) + "=" + v
	}

	// Build module string
	var moduleStr string
	if e.bypassModule != "" {
		moduleStr = pterm.FgCyan.Sprintf("[%s] ", e.bypassModule)
	}

	// Build debug token string
	var tokenStr string
	if e.debugToken != "" {
		tokenStr = pterm.FgYellow.Sprintf("[%s] ", e.debugToken)
	}

	// Format and print the message
	message := moduleStr + tokenStr + format + meta
	e.printer.Printfln(message, args...) // Use Printfln instead of Fprintf
}

// Helper methods for Event
func (e *Event) BypassModule(module string) *Event {
	if e == nil {
		return nil
	}
	e.bypassModule = module
	return e
}

func (e *Event) DebugToken(token string) *Event {
	if e == nil {
		return nil
	}
	e.debugToken = token
	return e
}

func (e *Event) Metadata(key, value string) *Event {
	if e == nil {
		return nil
	}
	e.metadata[key] = value
	return e
}

// Logger control methods
func (l *Logger) EnableDebug() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.debug = true
}

func (l *Logger) EnableVerbose() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.verbose = true
}

// Add these methods back
func (l *Logger) IsDebugEnabled() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.debug
}

func (l *Logger) IsVerboseEnabled() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.verbose
}

// And these package-level functions
func IsDebugEnabled() bool {
	return DefaultLogger.IsDebugEnabled()
}

func IsVerboseEnabled() bool {
	return DefaultLogger.IsVerboseEnabled()
}

// package logger

// import (
// 	"bytes"
// 	"fmt"
// 	"sync"

// 	"github.com/jedib0t/go-pretty/v6/text"
// )

// ///Information
// // Enable debug/verbose if needed
// // logger.DefaultLogger.EnableDebug()
// // logger.DefaultLogger.EnableVerbose()

// // // Basic logging
// // logger.Info().Msgf("Starting scan...")
// // logger.Error().Msgf("Error occurred: %v", err)

// // // With metadata
// // logger.Info().Str("module", "scanner").Msgf("Scan complete")

// // // Debug with Debug Token
// // logger.Debug().WithToken(debugToken).Msgf("Sending request...")

// // // Colored output
// // logger.PrintGreen("Success!")
// //

// const (
// 	labelInfo    = "ℹ️"
// 	labelWarning = "⚠️"
// 	labelError   = "❌"
// 	labelDebug   = "[DEBUG]"
// 	labelVerbose = "📜"
// 	labelDone    = "✅"
// )

// const (
// 	labelInfoFallback    = "[INFO]"
// 	labelWarningFallback = "[WARNING]"
// 	labelErrorFallback   = "[ERROR]"
// 	labelDebugFallback   = "[DEBUG]"
// 	labelVerboseFallback = "[VERBOSE]"
// 	labelDoneFallback    = "[DONE]"
// )

// var (
// 	DefaultLogger *Logger
// )

// func init() {
// 	DefaultLogger = &Logger{
// 		buffer:  &bytes.Buffer{},
// 		mu:      sync.Mutex{},
// 		verbose: false,
// 		debug:   false,
// 	}
// }

// type Logger struct {
// 	buffer  *bytes.Buffer
// 	mu      sync.Mutex
// 	verbose bool
// 	debug   bool
// }

// type Event struct {
// 	logger       *Logger
// 	message      string
// 	debugToken   string // For debug messages
// 	bypassModule string
// 	metadata     map[string]string
// 	isVerbose    bool
// 	isError      bool
// 	isWarning    bool
// 	isDone       bool
// }

// func (l *Logger) EnableVerbose() {
// 	l.mu.Lock()
// 	defer l.mu.Unlock()
// 	l.verbose = true
// }

// func (l *Logger) EnableDebug() {
// 	l.mu.Lock()
// 	defer l.mu.Unlock()
// 	l.debug = true
// }

// func (l *Logger) IsDebugEnabled() bool {
// 	l.mu.Lock()
// 	defer l.mu.Unlock()
// 	return l.debug
// }

// func IsDebugEnabled() bool {
// 	return DefaultLogger.IsDebugEnabled()
// }

// // Core logging methods that return *Event
// func Info() *Event {
// 	return DefaultLogger.newEvent()
// }

// func Error() *Event {
// 	e := DefaultLogger.newEvent()
// 	e.isError = true
// 	return e
// }

// func Debug() *Event {
// 	if !DefaultLogger.debug {
// 		return nil
// 	}
// 	return DefaultLogger.newEvent()
// }

// func Verbose() *Event {
// 	if !DefaultLogger.verbose {
// 		return nil
// 	}
// 	e := DefaultLogger.newEvent()
// 	e.isVerbose = true
// 	return e
// }

// func Warning() *Event {
// 	e := DefaultLogger.newEvent()
// 	e.isWarning = true
// 	return e
// }

// func Done() *Event {
// 	e := DefaultLogger.newEvent()
// 	e.isDone = true
// 	return e
// }

// // Print methods for colored output
// func PrintYellow(format string, args ...interface{}) {
// 	DefaultLogger.print(text.FgYellow, format, args...)
// }

// func PrintGreen(format string, args ...interface{}) {
// 	DefaultLogger.print(text.FgGreen, format, args...)
// }

// func PrintCyan(format string, args ...interface{}) {
// 	DefaultLogger.print(text.FgCyan, format, args...)
// }

// // Event methods
// func (e *Event) Msgf(format string, args ...interface{}) {
// 	if e == nil {
// 		return
// 	}
// 	e.message = fmt.Sprintf(format, args...)
// 	e.logger.log(e)
// }

// func (e *Event) Msg(message string) {
// 	if e == nil {
// 		return
// 	}
// 	e.message = message
// 	e.logger.log(e)
// }

// func (e *Event) BypassModule(module string) *Event {
// 	if e == nil {
// 		return nil
// 	}
// 	e.bypassModule = module
// 	return e
// }

// func (e *Event) DebugToken(token string) *Event {
// 	if e == nil {
// 		return nil
// 	}
// 	e.debugToken = token
// 	return e
// }

// // Add more context to the log message "status
// func (e *Event) Metadata(key, value string) *Event {
// 	if e == nil {
// 		return nil
// 	}
// 	if e.metadata == nil {
// 		e.metadata = make(map[string]string)
// 	}
// 	e.metadata[key] = value
// 	return e
// }

// // Logger methods
// func (l *Logger) newEvent() *Event {
// 	return &Event{
// 		logger:   l,
// 		metadata: make(map[string]string),
// 	}
// }

// func (l *Logger) log(e *Event) {
// 	l.mu.Lock()
// 	defer l.mu.Unlock()

// 	l.buffer.Reset()

// 	// Build metadata string
// 	var meta string
// 	for k, v := range e.metadata {
// 		meta += fmt.Sprintf(" %s=%s", text.Bold.Sprint(k), v)
// 	}

// 	// Build bypass module string if present
// 	var moduleStr string
// 	if e.bypassModule != "" {
// 		moduleStr = text.Colors{text.FgCyan, text.Bold}.Sprintf("[%s] ", e.bypassModule)
// 	}

// 	var header string
// 	switch {
// 	case e.debugToken != "":
// 		header = text.Colors{text.BgHiRed, text.FgWhite, text.Bold}.Sprint(labelDebug)
// 		token := text.Colors{text.FgYellow, text.Bold}.Sprintf("[%s]", e.debugToken)
// 		fmt.Printf("%s %s %s%s%s\n", header, token, moduleStr, e.message, meta)
// 	case e.isVerbose:
// 		header = text.Colors{text.FgBlue, text.Bold}.Sprint(labelVerbose)
// 		fmt.Printf("%s %s%s%s\n", header, moduleStr, e.message, meta)
// 	case e.isError:
// 		header = text.Colors{text.FgRed, text.Bold}.Sprint(labelError)
// 		fmt.Printf("%s %s%s%s\n", header, moduleStr, e.message, meta)
// 	case e.isWarning:
// 		header = text.Colors{text.FgYellow, text.Bold}.Sprint(labelWarning)
// 		fmt.Printf("%s %s%s%s\n", header, moduleStr, e.message, meta)
// 	case e.isDone:
// 		header = text.Colors{text.FgGreen, text.Bold}.Sprint(labelDone)
// 		fmt.Printf("%s %s%s%s\n", header, moduleStr, e.message, meta)
// 	default:
// 		header = text.Colors{text.FgGreen, text.Bold}.Sprint(labelInfo)
// 		fmt.Printf("%s %s%s%s\n", header, moduleStr, e.message, meta)
// 	}
// }

// func (l *Logger) print(color text.Color, format string, args ...interface{}) {
// 	l.mu.Lock()
// 	defer l.mu.Unlock()

// 	msg := fmt.Sprintf(format, args...)
// 	fmt.Printf("%s\n", color.Sprint(msg))
// }
