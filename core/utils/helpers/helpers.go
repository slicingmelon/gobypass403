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

// SanitizeNonPrintableBytesForCurl sanitizes non-printable bytes in a byte slice
// by URL-encoding them, making the curl command actually executable
func SanitizeNonPrintableBytesForCurl(input []byte) string {
	var sb strings.Builder
	sb.Grow(len(input))

	for _, b := range input {
		// Keep printable ASCII (32-126), LF (10), CR (13)
		if (b >= 32 && b <= 126) || b == 10 || b == 13 {
			sb.WriteByte(b)
		} else {
			// URL-encode non-printable bytes for curl compatibility
			sb.WriteString(fmt.Sprintf("%%%02X", b))
		}
	}
	return sb.String()
}

// SplitCurlCommandMultiline splits long curl commands into multiple lines
// with proper OS-specific line continuation characters and formatting
func SplitCurlCommandMultiline(curlCmd string, maxLineLength int) string {
	if len(curlCmd) <= maxLineLength {
		return curlCmd
	}

	// Detect OS for line continuation
	var lineContinuation string
	var indent string
	if runtime.GOOS == "windows" {
		lineContinuation = " `"
		indent = "  "
	} else {
		lineContinuation = " \\"
		indent = "  "
	}

	var result strings.Builder
	words := strings.Fields(curlCmd)
	if len(words) == 0 {
		return curlCmd
	}

	currentLine := words[0] // Start with first word (curl/curl.exe)
	isFirstLine := true

	for i := 1; i < len(words); i++ {
		word := words[i]

		// Check if adding this word would exceed max length
		testLine := currentLine + " " + word
		if len(testLine) > maxLineLength && len(currentLine) > 0 {
			// Write current line with continuation
			if isFirstLine {
				result.WriteString(currentLine)
				isFirstLine = false
			} else {
				result.WriteString(indent + currentLine)
			}
			result.WriteString(lineContinuation)
			result.WriteString("\n")

			// Start new line with current word
			currentLine = word
		} else {
			// Add word to current line
			if currentLine == words[0] {
				currentLine = testLine // First line
			} else {
				currentLine = currentLine + " " + word
			}
		}
	}

	// Add the final line
	if isFirstLine {
		result.WriteString(currentLine)
	} else {
		result.WriteString(indent + currentLine)
	}

	return result.String()
}

// IsIPv4 works the same way as net.ParseIP,
// but without check for IPv6 case and without returning net.IP slice, whereby IsIPv4 makes no allocations.
// from gofiber/utils
func IsIPv4(s string) bool {
	for i := 0; i < net.IPv4len; i++ {
		if len(s) == 0 {
			return false
		}

		if i > 0 {
			if s[0] != '.' {
				return false
			}
			s = s[1:]
		}

		n, ci := 0, 0

		for ci = 0; ci < len(s) && '0' <= s[ci] && s[ci] <= '9'; ci++ {
			n = n*10 + int(s[ci]-'0')
			if n > 0xFF {
				return false
			}
		}

		if ci == 0 || (ci > 1 && s[0] == '0') {
			return false
		}

		s = s[ci:]
	}

	return len(s) == 0
}

// IsIPv6 works the same way as net.ParseIP,
// but without check for IPv4 case and without returning net.IP slice, whereby IsIPv6 makes no allocations.
// from gofiber/utils
func IsIPv6(s string) bool {
	ellipsis := -1 // position of ellipsis in ip

	// Might have leading ellipsis
	if len(s) >= 2 && s[0] == ':' && s[1] == ':' {
		ellipsis = 0
		s = s[2:]
		// Might be only ellipsis
		if len(s) == 0 {
			return true
		}
	}

	// Loop, parsing hex numbers followed by colon.
	i := 0
	for i < net.IPv6len {
		// Hex number.
		n, ci := 0, 0

		for ci = 0; ci < len(s); ci++ {
			if '0' <= s[ci] && s[ci] <= '9' {
				n *= 16
				n += int(s[ci] - '0')
			} else if 'a' <= s[ci] && s[ci] <= 'f' {
				n *= 16
				n += int(s[ci]-'a') + 10
			} else if 'A' <= s[ci] && s[ci] <= 'F' {
				n *= 16
				n += int(s[ci]-'A') + 10
			} else {
				break
			}
			if n > 0xFFFF {
				return false
			}
		}
		if ci == 0 || n > 0xFFFF {
			return false
		}

		if ci < len(s) && s[ci] == '.' {
			if ellipsis < 0 && i != net.IPv6len-net.IPv4len {
				return false
			}
			if i+net.IPv4len > net.IPv6len {
				return false
			}

			if !IsIPv4(s) {
				return false
			}

			s = ""
			i += net.IPv4len
			break
		}

		// Save this 16-bit chunk.
		i += 2

		// Stop at end of string.
		s = s[ci:]
		if len(s) == 0 {
			break
		}

		// Otherwise must be followed by colon and more.
		if s[0] != ':' || len(s) == 1 {
			return false
		}
		s = s[1:]

		// Look for ellipsis.
		if s[0] == ':' {
			if ellipsis >= 0 { // already have one
				return false
			}
			ellipsis = i
			s = s[1:]
			if len(s) == 0 { // can be at end
				break
			}
		}
	}

	// Must have used entire string.
	if len(s) != 0 {
		return false
	}

	// If didn't parse enough, expand ellipsis.
	if i < net.IPv6len {
		if ellipsis < 0 {
			return false
		}
	} else if ellipsis >= 0 {
		// Ellipsis must represent at least one 0 group.
		return false
	}
	return true
}
