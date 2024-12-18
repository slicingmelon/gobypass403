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
	cyanColor    *color.Color

	// Add these fields
	verboseEnabled bool
	debugEnabled   bool
}

var globalLogger *Logger

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
	LogCyan    func(format string, v ...interface{})

	LogInfoln    func(format string, v ...interface{})
	LogVerboseln func(format string, v ...interface{})
	LogDebugln   func(format string, v ...interface{})
	LogErrorln   func(format string, v ...interface{})
	LogYellowln  func(format string, v ...interface{})
	LogOrangeln  func(format string, v ...interface{})
	LogGreenln   func(format string, v ...interface{})
	LogBlueln    func(format string, v ...interface{})
	LogPurpleln  func(format string, v ...interface{})
	LogGrayln    func(format string, v ...interface{})
	LogTealln    func(format string, v ...interface{})
	LogPinkln    func(format string, v ...interface{})
	LogCyanln    func(format string, v ...interface{})

	// Color-only functions (without newlines)
	Yellow func(format string, v ...interface{}) string
	Orange func(format string, v ...interface{}) string
	Green  func(format string, v ...interface{}) string
	Blue   func(format string, v ...interface{}) string
	Purple func(format string, v ...interface{}) string
	Gray   func(format string, v ...interface{}) string
	Teal   func(format string, v ...interface{}) string
	Pink   func(format string, v ...interface{}) string
	Cyan   func(format string, v ...interface{}) string
)

// init initializes the global logger and its functions
func init() {
	color.NoColor = false
	globalLogger = NewLogger()

	// Initialize regular logging functions (without newlines)
	LogInfo = globalLogger.LogInfo
	LogVerbose = globalLogger.LogVerbose
	LogDebug = globalLogger.LogDebug
	LogError = globalLogger.LogError
	LogYellow = globalLogger.LogYellow
	LogOrange = globalLogger.LogOrange
	LogGreen = globalLogger.LogGreen
	LogBlue = globalLogger.LogBlue
	LogPurple = globalLogger.LogPurple
	LogGray = globalLogger.LogGray
	LogTeal = globalLogger.LogTeal
	LogPink = globalLogger.LogPink
	LogCyan = globalLogger.LogCyan

	// Initialize ln variants (with newlines)
	LogInfoln = globalLogger.LogInfoln
	LogVerboseln = globalLogger.LogVerboseln
	LogDebugln = globalLogger.LogDebugln
	LogErrorln = globalLogger.LogErrorln
	LogYellowln = globalLogger.LogYellowln
	LogOrangeln = globalLogger.LogOrangeln
	LogGreenln = globalLogger.LogGreenln
	LogBlueln = globalLogger.LogBlueln
	LogPurpleln = globalLogger.LogPurpleln
	LogGrayln = globalLogger.LogGrayln
	LogTealln = globalLogger.LogTealln
	LogPinkln = globalLogger.LogPinkln
	LogCyanln = globalLogger.LogCyanln

	// Initialize color-only functions
	Yellow = globalLogger.yellowColor.Sprintf
	Orange = globalLogger.orangeColor.Sprintf
	Green = globalLogger.greenColor.Sprintf
	Blue = globalLogger.blueColor.Sprintf
	Purple = globalLogger.purpleColor.Sprintf
	Gray = globalLogger.grayColor.Sprintf
	Teal = globalLogger.tealColor.Sprintf
	Pink = globalLogger.pinkColor.Sprintf
	Cyan = globalLogger.cyanColor.Sprintf
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
		cyanColor:    color.New(color.FgHiCyan),
	}
}

// Add these global functions
func EnableVerbose() {
	globalLogger.EnableVerbose()
}

func EnableDebug() {
	globalLogger.EnableDebug()
}

// global utility functions to know if -d was passed as cli argument
func IsDebugEnabled() bool {
	return globalLogger.debugEnabled
}

// global utility function to know if -v was passed as cli argument
func IsVerboseEnabled() bool {
	return globalLogger.verboseEnabled
}

// EnableVerbose enables verbose logging
func (l *Logger) EnableVerbose() {
	l.verboseEnabled = true
}

// EnableDebug enables debug logging
func (l *Logger) EnableDebug() {
	l.debugEnabled = true
}

// Logger methods (with newlines)
func (l *Logger) LogInfo(format string, v ...interface{}) {
	l.infoColor.Printf("[INFO] "+format+"\n", v...)
}

func (l *Logger) LogInfoln(format string, v ...interface{}) {
	l.infoColor.Printf(format+"\n", v...)
}

func (l *Logger) LogVerbose(format string, v ...interface{}) {
	if l.verboseEnabled {
		l.verboseColor.Printf("[VERBOSE] "+format+"\n", v...)
	}
}

func (l *Logger) LogVerboseln(format string, v ...interface{}) {
	if l.verboseEnabled {
		l.verboseColor.Printf(format+"\n", v...)
	}
}

func (l *Logger) LogDebug(format string, v ...interface{}) {
	if l.debugEnabled {
		l.debugColor.Printf("[DEBUG] "+format+"\n", v...)
	}
}

func (l *Logger) LogDebugln(format string, v ...interface{}) {
	if l.debugEnabled {
		l.debugColor.Printf(format+"\n", v...)
	}
}

func (l *Logger) LogError(format string, v ...interface{}) {
	l.errorColor.Printf("[ERROR] "+format+"\n", v...)
}

func (l *Logger) LogErrorln(format string, v ...interface{}) {
	l.errorColor.Printf("[ERROR] "+format+"\n", v...)
}

func (l *Logger) LogYellow(format string, v ...interface{}) {
	l.yellowColor.Printf(format, v...)
}

func (l *Logger) LogYellowln(format string, v ...interface{}) {
	l.yellowColor.Printf(format+"\n", v...)
}

func (l *Logger) LogCyan(format string, v ...interface{}) {
	l.cyanColor.Printf(format, v...)
}

func (l *Logger) LogCyanln(format string, v ...interface{}) {
	l.cyanColor.Printf(format+"\n", v...)
}

func (l *Logger) LogOrange(format string, v ...interface{}) {
	l.orangeColor.Printf(format, v...)
}

func (l *Logger) LogOrangeln(format string, v ...interface{}) {
	l.orangeColor.Printf(format+"\n", v...)
}

func (l *Logger) LogGreen(format string, v ...interface{}) {
	l.greenColor.Printf(format, v...)
}

func (l *Logger) LogGreenln(format string, v ...interface{}) {
	l.greenColor.Printf(format+"\n", v...)
}

func (l *Logger) LogBlue(format string, v ...interface{}) {
	l.blueColor.Printf(format, v...)
}

func (l *Logger) LogBlueln(format string, v ...interface{}) {
	l.blueColor.Printf(format+"\n", v...)
}

func (l *Logger) LogPurple(format string, v ...interface{}) {
	l.purpleColor.Printf(format, v...)
}

func (l *Logger) LogPurpleln(format string, v ...interface{}) {
	l.purpleColor.Printf(format+"\n", v...)
}

func (l *Logger) LogPinkln(format string, v ...interface{}) {
	l.pinkColor.Printf(format+"\n", v...)
}

func (l *Logger) LogGray(format string, v ...interface{}) {
	l.grayColor.Printf(format, v...)
}

func (l *Logger) LogGrayln(format string, v ...interface{}) {
	l.grayColor.Printf(format+"\n", v...)
}

func (l *Logger) LogTeal(format string, v ...interface{}) {
	l.tealColor.Printf(format, v...)
}

func (l *Logger) LogTealln(format string, v ...interface{}) {
	l.tealColor.Printf(format+"\n", v...)
}

func (l *Logger) LogPink(format string, v ...interface{}) {
	l.pinkColor.Printf(format, v...)
}

func BlueString(format string, a ...interface{}) string {
	return globalLogger.blueColor.Sprintf(format, a...)
}

func YellowString(format string, a ...interface{}) string {
	return globalLogger.yellowColor.Sprintf(format, a...)
}

func GreenString(format string, a ...interface{}) string {
	return globalLogger.greenColor.Sprintf(format, a...)
}

func PurpleString(format string, a ...interface{}) string {
	return globalLogger.purpleColor.Sprintf(format, a...)
}

func OrangeString(format string, a ...interface{}) string {
	return globalLogger.orangeColor.Sprintf(format, a...)
}

func TealString(format string, a ...interface{}) string {
	return globalLogger.tealColor.Sprintf(format, a...)
}

func GrayString(format string, a ...interface{}) string {
	return globalLogger.grayColor.Sprintf(format, a...)
}

func PinkString(format string, a ...interface{}) string {
	return globalLogger.pinkColor.Sprintf(format, a...)
}

func CyanString(format string, a ...interface{}) string {
	return globalLogger.cyanColor.Sprintf(format, a...)
}
