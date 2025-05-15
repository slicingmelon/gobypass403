/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package helpers

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"
	"unsafe"

	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
)

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

	GB403Logger.Verbose().Msgf("Split host: %q port: %q", host, port)
	return net.ParseIP(host) != nil
}

// Update IsDNSName with debugging
func IsDNSName(str string) bool {
	GB403Logger.Verbose().Msgf("Checking if string is DNS name: %q", str)

	host, port, err := net.SplitHostPort(str)
	if err != nil {
		host = str
		GB403Logger.Verbose().Msgf("Using full string as hostname: %q", host)
	} else {
		GB403Logger.Verbose().Msgf("Split host: %q port: %q", host, port)
	}

	if host == "" {
		GB403Logger.Verbose().Msgf("Empty hostname")
		return false
	}

	if len(strings.Replace(host, ".", "", -1)) > 255 {
		GB403Logger.Verbose().Msgf("Hostname too long (>255 chars)")
		return false
	}

	GB403Logger.Verbose().Msgf("DNS regex match result: %v", rxDNSName.MatchString(host))
	return !IsIP(host) && rxDNSName.MatchString(host)
}

// Simple hosts file parser
func ResolveThroughSystemHostsFile(host string) string {
	// Handle localhost explicitly
	if host == "localhost" {
		return "127.0.0.1"
	}

	// Read /etc/hosts file
	hostsFile := "/etc/hosts"
	if runtime.GOOS == "windows" {
		hostsFile = `C:\Windows\System32\drivers\etc\hosts`
	}

	file, err := os.Open(hostsFile)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		ip := fields[0]
		for _, h := range fields[1:] {
			if h == host {
				return ip
			}
		}
	}

	if err := scanner.Err(); err != nil {
		GB403Logger.Error().
			Metadata("ResolveThroughSystemHostsFile()", "failed").
			Msgf("Error reading hosts file: %v\n", err)
		return ""
	}

	return ""
}

// String2Byte converts string to a byte slice without memory allocation.
// This conversion *does not* copy data. Note that casting via "([]byte)(string)" *does* copy data.
// Also note that you *should not* change the byte slice after conversion, because Go strings
// are treated as immutable. This would cause a segmentation violation panic.
func String2Byte(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

// Byte2String converts byte slice to a string without memory allocation.
// This conversion *does not* copy data. Note that casting via "(string)([]byte)" *does* copy data.
// Also note that you *should not* change the byte slice after conversion, because Go strings
// are treated as immutable. This would cause a segmentation violation panic.
func Byte2String(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// SanitizeNonPrintableBytes sanitizes non-printable bytes in a byte slice
// and returns a string with the sanitized bytes for better terminal output
func SanitizeNonPrintableBytes(input []byte) string {
	var sb strings.Builder
	sb.Grow(len(input))

	for _, b := range input {
		// Keep printable ASCII (32-126), LF (10), CR (13)
		if (b >= 32 && b <= 126) || b == 10 || b == 13 {
			sb.WriteByte(b)
			// Explicitly handle Tab separately and
			// replace with its escape sequence -- to test
		} else if b == 9 {
			sb.WriteString("\\x09")
		} else {
			// Replace others with Go-style hex escape
			sb.WriteString(fmt.Sprintf("\\x%02x", b))
		}
	}
	return sb.String()
}
