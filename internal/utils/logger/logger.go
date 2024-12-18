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

	// Initialize logging functions (with newlines)
	LogInfo = globalLogger.LogInfo
	LogVerbose = globalLogger.LogVerbose
	LogDebug = globalLogger.LogDebug
	LogError = globalLogger.LogError
	LogYellow = globalLogger.LogYellow
	LogOrange = globalLogger.LogOrange
	LogGreen = globalLogger.LogGreen
	LogBlue = globalLogger.LogBlue     // Fixed: was using logger.LogBlue
	LogPurple = globalLogger.LogPurple // Fixed: was using logger.LogPurple
	LogGray = globalLogger.LogGray
	LogTeal = globalLogger.LogTeal
	LogPink = globalLogger.LogPink
	LogCyan = globalLogger.LogCyan

	// Initialize color-only functions (without newlines)
	Yellow = globalLogger.yellowColor.Sprintf // Fixed: was using logger.yellowColor
	Orange = globalLogger.orangeColor.Sprintf // Fixed: was using logger.orangeColor
	Green = globalLogger.greenColor.Sprintf   // Fixed: was using logger.greenColor
	Blue = globalLogger.blueColor.Sprintf     // Fixed: was using logger.blueColor
	Purple = globalLogger.purpleColor.Sprintf // Fixed: was using logger.purpleColor
	Gray = globalLogger.grayColor.Sprintf     // Fixed: was using logger.grayColor
	Teal = globalLogger.tealColor.Sprintf     // Fixed: was using logger.tealColor
	Pink = globalLogger.pinkColor.Sprintf     // Fixed: was using logger.pinkColor
	Cyan = globalLogger.cyanColor.Sprintf     // Fixed: was using logger.cyanColor
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
	l.infoColor.Printf("\n[INFO] "+format+"\n", v...)
}

func (l *Logger) LogVerbose(format string, v ...interface{}) {
	if l.verboseEnabled {
		l.verboseColor.Printf("\n[VERBOSE] "+format+"\n", v...)
	}
}

func (l *Logger) LogDebug(format string, v ...interface{}) {
	if l.debugEnabled {
		l.debugColor.Printf("\n[DEBUG] "+format+"\n", v...)
	}
}

func (l *Logger) LogError(format string, v ...interface{}) {
	l.errorColor.Printf("\n[ERROR] "+format+"\n", v...)
}

func (l *Logger) LogYellow(format string, v ...interface{}) {
	l.yellowColor.Printf("\n"+format+"\n", v...)
}

func (l *Logger) LogCyan(format string, v ...interface{}) {
	l.cyanColor.Printf("\n"+format+"\n", v...)
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
