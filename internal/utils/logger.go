package utils

import (
	"fmt"

	"github.com/slicingmelon/go-bypass-403/internal/config"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
	colorGray   = "\033[90m"
	colorOrange = "\033[38;5;208m"
	colorPink   = "\033[38;5;206m"
	colorTeal   = "\033[38;5;51m"
	color
)

// LogInfo prints info messages (always shown)
func LogInfo(format string, v ...interface{}) {
	fmt.Printf("[INFO] "+format+"\n", v...)
}

// LogVe
func LogVerbose(format string, v ...interface{}) {
	if config.Verbose {
		fmt.Printf("\n"+colorCyan+format+colorReset+"\n", v...) // Cyan
	}
}

// LogDebug (only if -d and color purple)
func LogDebug(format string, v ...interface{}) {
	if config.Debug {
		fmt.Printf("\n"+colorPurple+format+colorReset+"\n", v...) // Purple
	}
}

// Red
func LogError(format string, v ...interface{}) {
	fmt.Printf("\n"+colorRed+"[ERROR] "+format+colorReset+"\n", v...)
}

func LogGreen(format string, v ...interface{}) {
	fmt.Printf("\n\033[32m"+format+"\033[0m\n", v...) // Green
}

func LogBlue(format string, v ...interface{}) {
	fmt.Printf("\n\033[34m"+format+"\033[0m\n", v...) // Blue
}

func LogYellow(format string, v ...interface{}) {
	fmt.Printf("\n\033[93m"+format+"\033[0m\n", v...) // Yellow
}

func LogRed(format string, v ...interface{}) {
	fmt.Printf("\n\033[91m"+format+"\033[0m\n", v...) // Red
}

func LogPurple(format string, v ...interface{}) {
	fmt.Printf(colorPurple+format+colorReset+"\n", v...) // Purple
}

func LogGray(format string, v ...interface{}) {
	fmt.Printf(colorGray+format+colorReset+"\n", v...) // Gray
}

func LogOrange(format string, v ...interface{}) {
	fmt.Printf(colorOrange+format+colorReset+"\n", v...) // Orange
}

func LogPink(format string, v ...interface{}) {
	fmt.Printf(colorPink+format+colorReset+"\n", v...) // Pink
}

func LogTeal(format string, v ...interface{}) {
	fmt.Printf(colorTeal+format+colorReset+"\n", v...) // Teal
}
