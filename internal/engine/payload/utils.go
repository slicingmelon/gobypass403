package payload

import (
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	charsetTable = func() [62]byte {
		// Initialize with 62 chars (26 lowercase + 26 uppercase + 10 digits)
		var table [62]byte

		// 0-9 (10 chars)
		for i := 0; i < 10; i++ {
			table[i] = byte(i) + '0'
		}

		// A-Z (26 chars)
		for i := 0; i < 26; i++ {
			table[i+10] = byte(i) + 'A'
		}

		// a-z (26 chars)
		for i := 0; i < 26; i++ {
			table[i+36] = byte(i) + 'a'
		}

		return table
	}()

	// Use a concurrent-safe random source
	rnd = rand.New(rand.NewSource(time.Now().UnixNano()))
	mu  sync.Mutex
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

// ReadPayloadsFromFile reads all payloads from the specified file
func ReadPayloadsFromFile(filename string) ([]string, error) {
	return ReadMaxPayloadsFromFile(filename, -1)
}

// ReadMaxPayloadsFromFile reads up to maxNum payloads from the specified file
// -1 means all payloads (lines)
func ReadMaxPayloadsFromFile(filename string, maxNum int) ([]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var payloads []string
	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		if i >= maxNum {
			break
		}
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
func HeadersToMap(headers []Header) map[string]string {
	m := make(map[string]string)
	for _, h := range headers {
		m[h.Header] = h.Value
	}
	return m
}

// GeneratePayloadSeed generates a random payload seed used later in debugging, etc
func GeneratePayloadSeed() string {
	b := make([]byte, 18)
	tableSize := uint32(len(charsetTable))

	mu.Lock()
	for i := range b {
		// Using uint32 for better performance than modulo
		b[i] = charsetTable[rnd.Uint32()%tableSize]
	}
	mu.Unlock()

	return string(b)
}
