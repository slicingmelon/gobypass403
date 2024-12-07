package experimentaltests

import (
	"bufio"
	"bytes"
	"os"
	"time"
)

// ANSI color codes
const (
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Reset   = "\033[0m"
	Bold    = "\033[1m"

	RequestTimeout = 5 * time.Second
)

var RandomServerPort int = 7594

// ReplaceNth replaces the nth occurrence of old with new in s
func ReplaceNthBytes(s, old, new []byte, n int) []byte {
	// Find all occurrences of old in s
	var positions []int
	pos := 0
	for {
		idx := bytes.Index(s[pos:], old)
		if idx == -1 {
			break
		}
		positions = append(positions, pos+idx)
		pos += idx + len(old)
	}

	// If n is out of bounds or no matches found, return original
	if n >= len(positions) {
		return s
	}

	// Create new slice with enough capacity
	result := make([]byte, 0, len(s)+len(new)-len(old))

	// Copy up to the nth occurrence
	result = append(result, s[:positions[n]]...)

	// Add the replacement
	result = append(result, new...)

	// Add the rest of the string
	result = append(result, s[positions[n]+len(old):]...)

	return result
}

func readPayloadsFileBytes(filePath string) ([][]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines [][]byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		if len(line) > 0 {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}
