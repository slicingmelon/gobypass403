package payload

import (
	"os"
	"strings"
)

// ReplaceNth replaces the nth occurrence of old with new in s
func ReplaceNth(s, old, new string, n int) string {
	if n < 1 {
		return s
	}

	count := 0
	pos := 0

	// Find the nth occurrence
	for count < n {
		nextPos := strings.Index(s[pos:], old)
		if nextPos == -1 {
			// Not enough occurrences found
			return s
		}

		pos += nextPos
		count++

		if count < n {
			pos += len(old) // Move past current occurrence
		}
	}

	// Replace the nth occurrence
	return s[:pos] + new + s[pos+len(old):]
}

// Helper function to read payloads from the specified file
func ReadPayloadsFile(filename string) ([]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var payloads []string
	for _, line := range strings.Split(string(content), "\n") {
		// Trim both spaces and \r\n
		line = strings.TrimSpace(line)
		if line != "" {
			payloads = append(payloads, line)
		}
	}

	return payloads, nil
}

// Helper function to check if a byte is a letter
func isLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

type Header struct {
	Header string
	Value  string
}

// Helper function to convert a slice of Header structs to a map
func headersToMap(headers []Header) map[string]string {
	m := make(map[string]string)
	for _, h := range headers {
		m[h.Header] = h.Value
	}
	return m
}
