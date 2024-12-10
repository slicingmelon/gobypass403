package utils

import (
	"github.com/fatih/color"
)

var (
	// Create color objects for reuse
	infoColor    = color.New(color.FgWhite)
	verboseColor = color.New(color.FgCyan)
	debugColor   = color.New(color.FgMagenta)
	errorColor   = color.New(color.FgRed, color.Bold)
	greenColor   = color.New(color.FgGreen)
	blueColor    = color.New(color.FgBlue)
	yellowColor  = color.New(color.FgYellow)
	purpleColor  = color.New(color.FgMagenta)
	grayColor    = color.New(color.FgHiBlack)
	orangeColor  = color.New(color.FgHiRed)
	pinkColor    = color.New(color.FgHiMagenta)
	tealColor    = color.New(color.FgHiCyan)
)

// LogInfo prints info messages (always shown)
func LogInfo(format string, v ...interface{}) {
	infoColor.Printf("[INFO] "+format+"\n", v...)
}

// LogVerbose prints verbose messages (only if -v)
func LogVerbose(format string, v ...interface{}) {
	verboseColor.Printf("\n[VERBOSE] "+format+"\n", v...)
}

// LogDebug prints debug messages (only if -d)
func LogDebug(format string, v ...interface{}) {
	debugColor.Printf("\n[DEBUG] "+format+"\n", v...)
}

// LogError prints error messages
func LogError(format string, v ...interface{}) {
	errorColor.Printf("\n[ERROR] "+format+"\n", v...)
}

// LogGreen prints green text
func LogGreen(format string, v ...interface{}) {
	greenColor.Printf("\n"+format+"\n", v...)
}

// LogBlue prints blue text
func LogBlue(format string, v ...interface{}) {
	blueColor.Printf("\n"+format+"\n", v...)
}

// LogYellow prints yellow text
func LogYellow(format string, v ...interface{}) {
	yellowColor.Printf("\n"+format+"\n", v...)
}

// LogRed prints red text
func LogRed(format string, v ...interface{}) {
	errorColor.Printf("\n"+format+"\n", v...)
}

// LogPurple prints purple text
func LogPurple(format string, v ...interface{}) {
	purpleColor.Printf(format+"\n", v...)
}

// LogGray prints gray text
func LogGray(format string, v ...interface{}) {
	grayColor.Printf(format+"\n", v...)
}

// LogOrange prints orange text
func LogOrange(format string, v ...interface{}) {
	orangeColor.Printf(format+"\n", v...)
}

// LogPink prints pink text
func LogPink(format string, v ...interface{}) {
	pinkColor.Printf(format+"\n", v...)
}

// LogTeal prints teal text
func LogTeal(format string, v ...interface{}) {
	tealColor.Printf(format+"\n", v...)
}
