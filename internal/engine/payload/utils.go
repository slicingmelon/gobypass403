package payload

import (
	"embed"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
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

//go:embed ../../payloads/*
var DefaultPayloadsDir embed.FS

// GetToolDir returns the tool's data directory path
func GetToolDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user config directory: %w", err)
	}
	return filepath.Join(configDir, "go-bypass-403"), nil
}

// GetPayloadsDir returns the payloads directory path
func GetPayloadsDir() (string, error) {
	toolDir, err := GetToolDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(toolDir, "payloads"), nil
}

// InitializePayloads copies default payloads to the tool directory
func InitializePayloadsDir(forceUpdate bool) error {
	payloadsDir, err := GetPayloadsDir()
	if err != nil {
		return fmt.Errorf("failed to get payloads directory: %w", err)
	}

	// Create payloads directory if it doesn't exist
	if err := os.MkdirAll(payloadsDir, 0755); err != nil {
		return fmt.Errorf("failed to create payloads directory: %w", err)
	}

	// Read embedded payloads directory
	entries, err := DefaultPayloadsDir.ReadDir("payloads")
	if err != nil {
		return fmt.Errorf("failed to read embedded payloads: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		srcPath := filepath.Join("payloads", entry.Name())
		dstPath := filepath.Join(payloadsDir, entry.Name())

		// Skip if file exists and we're not forcing update
		if !forceUpdate {
			if _, err := os.Stat(dstPath); err == nil {
				logger.LogVerbose("Payload file already exists: %s", dstPath)
				continue
			}
		}

		// Copy payload file
		if err := CopyPayloadFile(srcPath, dstPath); err != nil {
			return fmt.Errorf("failed to copy payload file %s: %w", entry.Name(), err)
		}
		logger.LogVerbose("Copied payload file: %s", dstPath)
	}

	return nil
}

func CopyPayloadFile(src, dst string) error {
	data, err := DefaultPayloadsDir.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// ReadPayloadsFromFile reads all payloads from the specified file
func ReadPayloadsFromFile(filename string) ([]string, error) {
	return ReadMaxPayloadsFromFile(filename, -1)
}

// ReadMaxPayloadsFromFile reads up to maxNum payloads from the specified file
// -1 means all payloads (lines)
func ReadMaxPayloadsFromFile(filename string, maxNum int) ([]string, error) {
	payloadsDir, err := GetPayloadsDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get payloads directory: %w", err)
	}

	filepath := filepath.Join(payloadsDir, filepath.Base(filename))
	content, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload file: %w", err)
	}

	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	var payloads []string
	lines := strings.Split(text, "\n")

	logger.LogVerbose("Read %d raw lines from payload file", len(lines))

	for i, line := range lines {
		if maxNum != -1 && i >= maxNum {
			break
		}
		line = strings.TrimSpace(line)
		if line != "" {
			payloads = append(payloads, line)
		}
	}

	logger.LogVerbose("Processed %d valid payloads", len(payloads))
	return payloads, nil
}

// ReplaceNth replaces the Nth  occurrence of old with new in s
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
