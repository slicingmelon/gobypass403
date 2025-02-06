package logger

import (
	"sync"

	"github.com/pterm/pterm"
)

type Logger struct {
	mu      sync.Mutex
	verbose bool
	debug   bool
}

var DefaultLogger *Logger

func init() {
	DefaultLogger = &Logger{
		verbose: false,
		debug:   false,
	}

	// stupid pterm
	pterm.EnableDebugMessages()

	// // Configure pterm styles
	// pterm.Info.Prefix = pterm.Prefix{
	// 	Text:  "INFO",
	// 	Style: pterm.NewStyle(pterm.BgBlue, pterm.FgBlack),
	// }

	// pterm.Debug.Prefix = pterm.Prefix{
	// 	Text:  "DEBUG",
	// 	Style: pterm.NewStyle(pterm.BgGray, pterm.FgWhite), // Changed to white text for better visibility
	// }

	// pterm.Success.Prefix = pterm.Prefix{
	// 	Text:  "SUCCESS",
	// 	Style: pterm.NewStyle(pterm.BgGreen, pterm.FgBlack),
	// }

	// pterm.Warning.Prefix = pterm.Prefix{
	// 	Text:  "WARNING",
	// 	Style: pterm.NewStyle(pterm.BgYellow, pterm.FgBlack),
	// }

	// pterm.Error.Prefix = pterm.Prefix{
	// 	Text:  "ERROR",
	// 	Style: pterm.NewStyle(pterm.BgRed, pterm.FgBlack),
	// }

}

type Event struct {
	logger       *Logger
	printer      pterm.PrefixPrinter
	bypassModule string
	debugToken   string
	metadata     map[string]string
}

func (l *Logger) newEvent(printer pterm.PrefixPrinter) *Event {
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
	if !DefaultLogger.IsDebugEnabled() {
		return nil
	}
	return DefaultLogger.newEvent(pterm.Debug)
}

func Verbose() *Event {
	if !DefaultLogger.verbose {
		return nil
	}
	return DefaultLogger.newEvent(pterm.Info)
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

func PrintGreen(format string, args ...interface{}) {
	DefaultLogger.mu.Lock()
	defer DefaultLogger.mu.Unlock()
	pterm.FgGreen.Printfln(format, args...)
}

func PrintYellow(format string, args ...interface{}) {
	DefaultLogger.mu.Lock()
	defer DefaultLogger.mu.Unlock()
	pterm.FgYellow.Printfln(format, args...)
}

func PrintCyan(format string, args ...interface{}) {
	DefaultLogger.mu.Lock()
	defer DefaultLogger.mu.Unlock()
	pterm.FgCyan.Printfln(format, args...)
}
