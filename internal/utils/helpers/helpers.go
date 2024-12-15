package helpers

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"math/rand"
	//"github.com/slicingmelon/go-bypass-403/internal/config"
	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

// Helper function to format bytes (so you can see human readable size)
func FormatBytesH(bytes int64) string {
	const unit = 1024
	if bytes < 0 {
		return "unknown"
	}
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(bytes)/float64(div), "KMGTPE"[exp])
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

// Helper function to format headers for logging
func formatHeaders(headers []Header) string {
	if len(headers) == 0 {
		return ""
	}
	return fmt.Sprintf(" [Headers: %v]", headers)
}

// Helper function to extract title from response body
func extractTitle(body string) string {
	var titleRegex = regexp.MustCompile(`(?i)<title>(.*?)</title>`)

	matches := titleRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// Helper function to generate random strings
func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// ----------------------------------------------------------------//
// URL Validation Stuff//
// Custom URL Validation, HTTPX probes and more //

// RFC 1035
var rxDNSName = regexp.MustCompile(`^([a-zA-Z0-9_]{1}[a-zA-Z0-9\-._]{0,61}[a-zA-Z0-9]{1}\.)*` +
	`([a-zA-Z0-9_]{1}[a-zA-Z0-9\-._]{0,61}[a-zA-Z0-9]{1}\.?)$`)

func IsIP(str string) bool {

	// Split host and port
	host, port, err := net.SplitHostPort(str)
	if err != nil {
		return net.ParseIP(str) != nil
	}

	logger.LogVerbose("Split host: %q port: %q", host, port)
	return net.ParseIP(host) != nil
}

// Update IsDNSName with debugging
func IsDNSName(str string) bool {
	logger.LogVerbose("[DEBUG] Checking if string is DNS name: %q", str)

	host, port, err := net.SplitHostPort(str)
	if err != nil {
		host = str
		logger.LogVerbose("[DEBUG] Using full string as hostname: %q", host)
	} else {
		logger.LogVerbose("Split host: %q port: %q", host, port)
	}

	if host == "" {
		logger.LogVerbose("[DEBUG] Empty hostname")
		return false
	}

	if len(strings.Replace(host, ".", "", -1)) > 255 {
		logger.LogVerbose("[DEBUG] Hostname too long (>255 chars)")
		return false
	}

	logger.LogVerbose("[DEBUG] DNS regex match result: %v", rxDNSName.MatchString(host))
	return !IsIP(host) && rxDNSName.MatchString(host)
}
