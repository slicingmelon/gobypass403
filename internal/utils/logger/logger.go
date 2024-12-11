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

// Global functions for logging (with newlines)
var (
	// Logging functions (with newlines)
	LogInfo    func(format string, v ...interface{})
	LogVerbose func(format string, v ...interface{})
	LogDebug   func(format string, v ...interface{})
	LogError   func(format string, v ...interface{})
	LogYellow  func(format string, v ...interface{})
	LogOrange  func(format string, v ...interface{})
	LogGreen   func(format string, v ...interface{})
	LogBlue    func(format string, v ...interface{})
	LogPurple  func(format string, v ...interface{})
	LogGray    func(format string, v ...interface{})
	LogTeal    func(format string, v ...interface{})
	LogPink    func(format string, v ...interface{})

	// Color-only functions (without newlines)
	Yellow func(format string, v ...interface{}) string
	Orange func(format string, v ...interface{}) string
	Green  func(format string, v ...interface{}) string
	Blue   func(format string, v ...interface{}) string
	Purple func(format string, v ...interface{}) string
	Gray   func(format string, v ...interface{}) string
	Teal   func(format string, v ...interface{}) string
	Pink   func(format string, v ...interface{}) string
)

// init initializes the global logger and its functions
func init() {
	logger := NewLogger()

	// Initialize logging functions (with newlines)
	LogInfo = logger.LogInfo
	LogVerbose = logger.LogVerbose
	LogDebug = logger.LogDebug
	LogError = logger.LogError
	LogYellow = logger.LogYellow
	LogOrange = logger.LogOrange
	LogGreen = logger.LogGreen
	LogBlue = logger.LogBlue
	LogPurple = logger.LogPurple
	LogGray = logger.LogGray
	LogTeal = logger.LogTeal
	LogPink = logger.LogPink

	// Initialize color-only functions (without newlines)
	Yellow = logger.yellowColor.Sprintf
	Orange = logger.orangeColor.Sprintf
	Green = logger.greenColor.Sprintf
	Blue = logger.blueColor.Sprintf
	Purple = logger.purpleColor.Sprintf
	Gray = logger.grayColor.Sprintf
	Teal = logger.tealColor.Sprintf
	Pink = logger.pinkColor.Sprintf
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

// Logger methods (with newlines)
func (l *Logger) LogInfo(format string, v ...interface{}) {
	l.infoColor.Printf("\n[INFO] "+format+"\n", v...)
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
