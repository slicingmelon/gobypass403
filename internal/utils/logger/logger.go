package logger

import (
	"github.com/fatih/color"
)

// Logger provides logging functionality
type Logger struct {
	infoColor    *color.Color
	verboseColor *color.Color
	debugColor   *color.Color
	errorColor   *color.Color
	greenColor   *color.Color
	blueColor    *color.Color
	yellowColor  *color.Color
	purpleColor  *color.Color
	grayColor    *color.Color
	orangeColor  *color.Color
	pinkColor    *color.Color
	tealColor    *color.Color
}

// Global functions for logging
var (
	Info    func(format string, v ...interface{})
	Verbose func(format string, v ...interface{})
	Debug   func(format string, v ...interface{})
	Error   func(format string, v ...interface{})
	Yellow  func(format string, v ...interface{})
	Orange  func(format string, v ...interface{})
	Green   func(format string, v ...interface{})
	Blue    func(format string, v ...interface{})
	Purple  func(format string, v ...interface{})
	Gray    func(format string, v ...interface{})
	Teal    func(format string, v ...interface{})
	Pink    func(format string, v ...interface{})
)

// init initializes the global logger and its functions
func init() {
	logger := NewLogger()

	// Initialize global logging functions
	Info = logger.LogInfo
	Verbose = logger.LogVerbose
	Debug = logger.LogDebug
	Error = logger.LogError
	Yellow = logger.LogYellow
	Orange = logger.LogOrange
	Green = logger.LogGreen
	Blue = logger.LogBlue
	Purple = logger.LogPurple
	Gray = logger.LogGray
	Teal = logger.LogTeal
	Pink = logger.LogPink
}

// NewLogger creates a new logger instance
func NewLogger() *Logger {
	return &Logger{
		infoColor:    color.New(color.FgWhite),
		verboseColor: color.New(color.FgCyan),
		debugColor:   color.New(color.FgMagenta),
		errorColor:   color.New(color.FgRed, color.Bold),
		greenColor:   color.New(color.FgGreen),
		blueColor:    color.New(color.FgBlue),
		yellowColor:  color.New(color.FgYellow),
		purpleColor:  color.New(color.FgMagenta),
		grayColor:    color.New(color.FgHiBlack),
		orangeColor:  color.New(color.FgHiRed),
		pinkColor:    color.New(color.FgHiMagenta),
		tealColor:    color.New(color.FgHiCyan),
	}
}

// Logger methods
func (l *Logger) LogInfo(format string, v ...interface{}) {
	l.infoColor.Printf("[INFO] "+format+"\n", v...)
}

func (l *Logger) LogVerbose(format string, v ...interface{}) {
	l.verboseColor.Printf("\n[VERBOSE] "+format+"\n", v...)
}

func (l *Logger) LogDebug(format string, v ...interface{}) {
	l.debugColor.Printf("\n[DEBUG] "+format+"\n", v...)
}

func (l *Logger) LogError(format string, v ...interface{}) {
	l.errorColor.Printf("\n[ERROR] "+format+"\n", v...)
}

func (l *Logger) LogYellow(format string, v ...interface{}) {
	l.yellowColor.Printf("\n"+format+"\n", v...)
}

func (l *Logger) LogOrange(format string, v ...interface{}) {
	l.orangeColor.Printf("\n"+format+"\n", v...)
}

func (l *Logger) LogGreen(format string, v ...interface{}) {
	l.greenColor.Printf("\n"+format+"\n", v...)
}

func (l *Logger) LogBlue(format string, v ...interface{}) {
	l.blueColor.Printf("\n"+format+"\n", v...)
}

func (l *Logger) LogPurple(format string, v ...interface{}) {
	l.purpleColor.Printf("\n"+format+"\n", v...)
}

func (l *Logger) LogGray(format string, v ...interface{}) {
	l.grayColor.Printf("\n"+format+"\n", v...)
}

func (l *Logger) LogTeal(format string, v ...interface{}) {
	l.tealColor.Printf("\n"+format+"\n", v...)
}

func (l *Logger) LogPink(format string, v ...interface{}) {
	l.pinkColor.Printf("\n"+format+"\n", v...)
}
