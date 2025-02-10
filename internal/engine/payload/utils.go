package payload

// This file contains various payload related utilities.

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
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
)

//go:embed payloads/*.lst
var DefaultPayloadsDir embed.FS

// GetToolDir returns the tool's data directory path
func GetToolDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user config directory: %v", err)
	}
	return filepath.Join(configDir, "go-bypass-403"), nil
}

// GetPayloadsDir returns the payloads directory path
func GetPayloadsDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user config directory: %w", err)
	}
	return filepath.Join(configDir, "go-bypass-403", "payloads"), nil
}

// InitializePayloadsDir ensures all payload files exist in the user's config directory
func InitializePayloadsDir() error {
	toolDir, err := GetToolDir()
	if err != nil {
		return fmt.Errorf("failed to get tool directory: %w", err)
	}

	payloadsDir := filepath.Join(toolDir, "payloads")
	if err := os.MkdirAll(payloadsDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create payloads directory: %w", err)
	}

	entries, err := DefaultPayloadsDir.ReadDir("payloads")
	if err != nil {
		return fmt.Errorf("failed to read embedded payloads: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		srcPath := fmt.Sprintf("payloads/%s", entry.Name())
		dstPath := filepath.Join(payloadsDir, entry.Name())

		// Copy only if file doesn't exist
		if _, err := os.Stat(dstPath); os.IsNotExist(err) {
			data, err := DefaultPayloadsDir.ReadFile(srcPath)
			if err != nil {
				return fmt.Errorf("failed to read embedded file %s: %w", srcPath, err)
			}
			if err := os.WriteFile(dstPath, data, 0644); err != nil {
				return fmt.Errorf("failed to write file %s: %w", dstPath, err)
			}
			GB403Logger.Verbose().Msgf("Created payload file: %s", dstPath)
		}
	}
	return nil
}

// UpdatePayloads forcefully updates all payload files
func UpdatePayloads() error {
	payloadsDir, err := GetPayloadsDir()
	if err != nil {
		return fmt.Errorf("failed to get payloads directory: %w", err)
	}

	// Force update all files
	entries, err := DefaultPayloadsDir.ReadDir("payloads")
	if err != nil {
		return fmt.Errorf("failed to read embedded payloads: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		data, err := DefaultPayloadsDir.ReadFile(filepath.Join("payloads", entry.Name()))
		if err != nil {
			return fmt.Errorf("failed to read embedded file %s: %w", entry.Name(), err)
		}

		dstPath := filepath.Join(payloadsDir, entry.Name())
		if err := os.WriteFile(dstPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write file %s: %w", dstPath, err)
		}
		GB403Logger.Verbose().Msgf("Updated payload file: %s", dstPath)
	}
	return nil
}

// CopyPayloadFile reads a file from the embedded filesystem and writes it to the destination path
func CopyPayloadFile(src, dst string) error {
	data, err := DefaultPayloadsDir.ReadFile(src)
	if err != nil {
		return fmt.Errorf("failed to read embedded file %s: %w", src, err)
	}
	if err := os.WriteFile(dst, data, 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %w", dst, err)
	}
	return nil
}

// ReadPayloadsFromFile reads all payloads from the specified file
func ReadPayloadsFromFile(filename string) ([]string, error) {
	// Try reading from local directory first
	payloads, err := ReadMaxPayloadsFromFile(filename, -1)
	if err == nil {
		return payloads, nil
	}

	// Fallback to embedded FS if local read fails
	content, err := DefaultPayloadsDir.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload file %s: %w", filename, err)
	}

	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	var embeddedPayloads []string
	lines := strings.Split(text, "\n")

	GB403Logger.Debug().Msgf("Read %d raw lines from embedded payload file", len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			embeddedPayloads = append(embeddedPayloads, line)
		}
	}

	GB403Logger.Debug().Msgf("Processed %d valid payloads", len(embeddedPayloads))
	return embeddedPayloads, nil
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

	GB403Logger.Debug().Msgf("Read %d raw lines from payload file", len(lines))

	for i, line := range lines {
		if maxNum != -1 && i >= maxNum {
			break
		}
		line = strings.TrimSpace(line)
		if line != "" {
			payloads = append(payloads, line)
		}
	}

	GB403Logger.Verbose().Msgf("Processed %d valid payloads", len(payloads))
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

type Headers struct {
	Header string
	Value  string
}

// Helper function to convert a slice of Header structs to a map
func HeadersToMap(headers []Headers) map[string]string {
	m := make(map[string]string)
	for _, h := range headers {
		m[h.Header] = h.Value
	}
	return m
}
