package helpers

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	//"github.com/slicingmelon/go-bypass-403/internal/config"
	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

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
