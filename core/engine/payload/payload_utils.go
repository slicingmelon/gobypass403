/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package payload

// This file contains various payload related utilities.
import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/slicingmelon/go-rawurlparser"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
	"golang.org/x/text/unicode/norm"
)

var (
	hexChars = []byte("0123456789ABCDEF")
)

//go:embed payloads/*.lst payloads/*.json
var DefaultPayloadsDir embed.FS

// GetToolDir returns the tool's data directory path
func GetToolDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user config directory: %v", err)
	}
	return filepath.Join(configDir, "gobypass403"), nil
}

// GetPayloadsDir returns the payloads directory path
func GetPayloadsDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user config directory: %w", err)
	}
	return filepath.Join(configDir, "gobypass403", "payloads"), nil
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
	// First ensure the directories exist
	payloadsDir, err := GetPayloadsDir()
	if err != nil {
		return fmt.Errorf("failed to get payloads directory: %w", err)
	}

	if err := os.MkdirAll(payloadsDir, 0755); err != nil {
		return fmt.Errorf("failed to create payloads directory: %w", err)
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

		// Use filepath.Join with "payloads" prefix for reading from embedded FS
		srcPath := fmt.Sprintf("payloads/%s", entry.Name())
		data, err := DefaultPayloadsDir.ReadFile(srcPath)
		if err != nil {
			return fmt.Errorf("failed to read embedded file %s: %w", srcPath, err)
		}

		dstPath := filepath.Join(payloadsDir, entry.Name())
		if err := os.WriteFile(dstPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write file %s: %w", dstPath, err)
		}
		GB403Logger.Info().Msgf("Updated payload file: %s", dstPath)
	}

	GB403Logger.Info().Msgf("All payloads updated successfully")
	return nil
}

// calculateSHA256 computes the SHA256 hash of byte data.
func calculateSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// CheckPayloadsConsistency compares embedded payloads with local ones.
// Returns true if consistent, false otherwise.
func CheckOutdatedPayloads() (bool, error) {
	localPayloadsDir, err := GetPayloadsDir()
	if err != nil {
		return false, fmt.Errorf("failed to get local payloads directory: %w", err)
	}

	embeddedEntries, err := DefaultPayloadsDir.ReadDir("payloads")
	if err != nil {
		return false, fmt.Errorf("failed to read embedded payloads directory: %w", err)
	}

	for _, entry := range embeddedEntries {
		if entry.IsDir() {
			continue
		}

		embeddedFileName := entry.Name()
		localFilePath := filepath.Join(localPayloadsDir, embeddedFileName)
		embeddedFilePath := "payloads/" + embeddedFileName // Path for embed FS

		// Check if local file exists
		if _, err := os.Stat(localFilePath); os.IsNotExist(err) {
			GB403Logger.Debug().Msgf("Local payload file missing: %s", localFilePath)
			return false, nil
		} else if err != nil {
			return false, fmt.Errorf("error checking local file %s: %w", localFilePath, err)
		}

		// Read embedded file content
		embeddedData, err := DefaultPayloadsDir.ReadFile(embeddedFilePath)
		if err != nil {
			return false, fmt.Errorf("failed to read embedded file %s: %w", embeddedFilePath, err)
		}

		// Read local file content
		localData, err := os.ReadFile(localFilePath)
		if err != nil {
			return false, fmt.Errorf("failed to read local file %s: %w", localFilePath, err)
		}

		// 4. Compare hashes
		embeddedHash := calculateSHA256(embeddedData)
		localHash := calculateSHA256(localData)

		if embeddedHash != localHash {
			GB403Logger.Debug().Msgf("Payload file mismatch (SHA256): %s (Embed: %s, Local: %s)",
				embeddedFileName, embeddedHash[:8], localHash[:8])
			return false, nil
		}
	}

	return true, nil
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

// Helper to read a JSON file
func ReadPayloadsFromJSONFile(filename string) ([]byte, error) {
	// Try reading from local directory first
	payloadsDir, err := GetPayloadsDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get payloads directory: %w", err)
	}

	localFile := payloadsDir + "/" + filename
	content, err := os.ReadFile(localFile)
	if err == nil {
		return content, nil
	}

	// Fallback to embedded FS
	return DefaultPayloadsDir.ReadFile("payloads/" + filename)
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

// Helper function to convert a slice of Header structs to a map
func HeadersToMap(headers []Headers) map[string]string {
	m := make(map[string]string)
	for _, h := range headers {
		m[h.Header] = h.Value
	}
	return m
}

// URLEncodeAll encodes each character in the input string to its percent-encoded representation
// It handles UTF-8 characters by encoding each byte of their UTF-8 representation
func URLEncodeAll(s string) string {
	// Pre-allocate buffer (3 bytes per character: %XX)
	buf := make([]byte, 0, len(s)*3)

	// Convert to bytes to properly handle UTF-8
	for _, b := range []byte(s) {
		buf = append(buf, '%')
		buf = append(buf, hexChars[b>>4])
		buf = append(buf, hexChars[b&15])
	}

	return string(buf)
}

// encodePathSpecialChars replaces literal '?' and '#' within a path string
// with their percent-encoded equivalents (%3F and %23).
func encodeQueryAndFragmentChars(path string) string {
	// Use strings.Builder for potentially better performance on multiple replacements
	var builder strings.Builder
	builder.Grow(len(path)) // Pre-allocate roughly the needed size
	for i := 0; i < len(path); i++ {
		char := path[i]
		switch char {
		case '?':
			builder.WriteString("%3F")
		case '#':
			builder.WriteString("%23")
		default:
			builder.WriteByte(char)
		}
	}
	return builder.String()
}

// isControlByte checks if a byte is an ASCII control character (0x00-0x1F, 0x7F)
func isControlByteASCII(b byte) bool {
	return (b <= 0x1F) || b == 0x7F
}

// isSpecialCharASCII checks if a byte is an ASCII special character (punctuation or symbol within 0-127)
// !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~
func isSpecialCharASCII(b byte) bool {
	// Ensure it's within ASCII range first
	if b > 127 {
		return false
	}
	// Use standard Go functions for ASCII range checks which are efficient
	// or check against a predefined string/map for ASCII punctuation/symbols if preferred.
	// Using unicode functions is fine as they handle ASCII correctly and efficiently.
	r := rune(b)
	return unicode.IsPunct(r) || unicode.IsSymbol(r)
}

// Helper function to check if a byte is a letter
func isLetterASCII(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isSpaceASCII(b byte) bool {
	return b == 0x20
}

// isAlphanumeric checks if a byte is a standard ASCII letter or digit.
func isAlphanumericASCII(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// BypassPayloadToBaseURL converts a bypass payload to base URL (scheme://host)
// ex BypassPayloadToBaseURLwithMake winner
/*
BenchmarkBypassPayloadToBaseURL
BenchmarkBypassPayloadToBaseURL/with_pool
BenchmarkBypassPayloadToBaseURL/with_pool-20
20745991	        60.15 ns/op	      32 B/op	       2 allocs/op
BenchmarkBypassPayloadToBaseURL/with_make
BenchmarkBypassPayloadToBaseURL/with_make-20
46353880	        28.99 ns/op	      24 B/op	       1 allocs/op
BenchmarkBypassPayloadToBaseURL/with_sprintf
BenchmarkBypassPayloadToBaseURL/with_sprintf-20
10295320	       120.5 ns/op	      56 B/op	       3 allocs/op
PASS
ok  	github.com/slicingmelon/gobypass403/tests/benchmark	5.679s

BenchmarkBypassPayloadToBaseURL/with_strings_builder - Added for comparison
*/
func BypassPayloadToBaseURL(bypassPayload BypassPayload) string {
	var sb strings.Builder
	sb.Grow(len(bypassPayload.Scheme) + 3 + len(bypassPayload.Host))
	sb.WriteString(bypassPayload.Scheme)
	sb.WriteString("://")
	sb.WriteString(bypassPayload.Host)
	return sb.String()
}

// TryNormalizationForms tries different normalization forms of a URL
func TryNormalizationForms(fullURL string) (string, error) {
	// Basic validation first
	if !strings.Contains(fullURL, "://") && !strings.Contains(fullURL, ":/") {
		return "", fmt.Errorf("invalid URL format: missing scheme separator")
	}

	// Try different normalization forms in order of preference
	normalizers := []struct {
		form norm.Form
		name string
	}{
		{norm.NFKC, "NFKC"},
		{norm.NFKD, "NFKD"},
		{norm.NFC, "NFC"},
		{norm.NFD, "NFD"},
	}

	var lastErr error
	for _, n := range normalizers {
		normalized := n.form.String(fullURL)
		if normalized != fullURL {
			GB403Logger.Debug().Msgf("Trying normalization form %s: %s -> %s",
				n.name, fullURL, normalized)
		}

		// Try parsing with this normalization
		if parsedURL, err := rawurlparser.RawURLParse(normalized); err == nil {
			// Additional validation
			if parsedURL.Scheme == "" || parsedURL.Host == "" {
				lastErr = fmt.Errorf("invalid URL: missing scheme or host")
				continue
			}
			return normalized, nil
		} else {
			lastErr = err
		}
	}

	// If all normalizations fail, return error
	return "", fmt.Errorf("URL validation failed: %w", lastErr)
}

// FullURLToBypassPayload converts a full URL to a bypass payload
func FullURLToBypassPayload(fullURL string, method string, headers []Headers) (BypassPayload, error) {
	// Try different normalization forms
	normalizedURL, err := TryNormalizationForms(fullURL)
	if err != nil {
		return BypassPayload{}, fmt.Errorf("invalid URL: %w", err)
	}

	parsedURL, err := rawurlparser.RawURLParse(normalizedURL)
	if err != nil {
		return BypassPayload{}, fmt.Errorf("failed to parse URL: %w", err)
	}

	return BypassPayload{
		Method:  method,
		Scheme:  parsedURL.Scheme,
		Host:    parsedURL.Host,
		RawURI:  parsedURL.Path,
		Headers: headers,
	}, nil
}

// BypassPayloadToFullURL converts a bypass payload to a full URL (utility function for unit tests)
func BypassPayloadToFullURL(bypassPayload BypassPayload) string {
	var sb strings.Builder
	sb.Grow(len(bypassPayload.Scheme) + 3 + len(bypassPayload.Host) + len(bypassPayload.RawURI))
	sb.WriteString(bypassPayload.Scheme)
	sb.WriteString("://")
	sb.WriteString(bypassPayload.Host)
	sb.WriteString(bypassPayload.RawURI)
	return sb.String()
}

// NormalizeHeaderKey canonicalizes a header key string.
// Example: "x-abc-test" becomes "X-Abc-Test"
// func NormalizeHeaderKey(key string) string {
// 	return textproto.CanonicalMIMEHeaderKey(key)
// }

func NormalizeHeaderKey(key string) string {
	if key == "" {
		return key
	}

	// Split by hyphens and capitalize each part
	parts := strings.Split(key, "-")
	for i, part := range parts {
		if len(part) > 0 {
			parts[i] = strings.ToUpper(part[:1]) + strings.ToLower(part[1:])
		}
	}
	return strings.Join(parts, "-")
}
