package experimentaltests

import (
	"bytes"
	"errors"
)

var (
	ErrEmptyURL   = errors.New("empty URL")
	ErrInvalidURL = errors.New("invalid URL format")
)

func addLeadingSlashBytes(dst, src []byte) []byte {
	// add leading slash for unix paths (byte[] version)
	if len(src) == 0 || src[0] != '/' {
		dst = append(dst, '/')
	}

	return dst
}

// Userinfo stores username and password info
type Userinfo struct {
	username    string
	password    string
	passwordSet bool
}

// ParseOptionsByte contains configuration options for URL parsing using []byte
type ParseOptions struct {
	FallbackScheme     []byte // Default scheme if none provided
	AllowMissingScheme bool   // If true, uses FallbackScheme when scheme is missing
}

// DefaultOptionsByte returns the default parsing options for byte-based parsing
func DefaultOptions() *ParseOptions {
	return &ParseOptions{
		FallbackScheme:     []byte("https"),
		AllowMissingScheme: true,
	}
}

type RawURLBytes struct {
	Original      []byte    // The original, unmodified URL bytes
	Scheme        []byte    // The URL scheme (e.g., "http", "https")
	Opaque        []byte    // For non-hierarchical URLs
	User          *Userinfo // username and password information (could also be converted to []byte-based)
	Host          []byte    // The host component (hostname + port)
	Path          []byte    // The path component, exactly as provided
	Query         []byte    // The query string without the leading '?'
	Fragment      []byte    // The fragment without the leading '#'
	RawRequestURI []byte    // Everything after host: /path?query#fragment
}

// RawURLParseByte parses URL with default options and returns []byte-based struct
// RawURLParseByte parses URL with default options and returns []byte-based struct
func RawURLParseBytes(rawURLBytes []byte) (*RawURLBytes, error) {
	return RawURLParseBytesWithOptions(rawURLBytes, DefaultOptions())
}

// RawURLParseByteWithOptions parses URL with custom options and returns []byte-based struct
func RawURLParseBytesWithOptions(rawURL []byte, opts *ParseOptions) (*RawURLBytes, error) {
	if len(rawURL) == 0 {
		return nil, ErrEmptyURL
	}

	result := &RawURLBytes{
		Original: append([]byte(nil), rawURL...), // make a copy to be safe
	}

	// Handle scheme
	schemeEnd := bytes.Index(rawURL, []byte("://"))
	remaining := rawURL

	if schemeEnd != -1 {
		result.Scheme = append([]byte(nil), rawURL[:schemeEnd]...)
		remaining = rawURL[schemeEnd+3:]
	} else {
		// Check for scheme without //
		if colonIndex := bytes.Index(rawURL, []byte(":")); colonIndex != -1 {
			beforeColon := rawURL[:colonIndex]
			if !bytes.Contains(beforeColon, []byte("/")) && !bytes.Contains(beforeColon, []byte(".")) {
				result.Scheme = append([]byte(nil), beforeColon...)
				result.Opaque = append([]byte(nil), rawURL[colonIndex+1:]...)
				return result, nil
			}
		}

		// Apply fallback scheme if configured
		if opts != nil && opts.AllowMissingScheme {
			result.Scheme = []byte(opts.FallbackScheme)
		}
	}

	// Split authority (host + optional userinfo) from path
	pathStart := bytes.Index(remaining, []byte("/"))
	authority := remaining
	if pathStart != -1 {
		authority = remaining[:pathStart]
		remaining = remaining[pathStart:]
	} else {
		remaining = []byte("/")
	}

	// Parse authority (user:pass@host:port)
	if atIndex := bytes.Index(authority, []byte("@")); atIndex != -1 {
		userinfo := authority[:atIndex]
		authority = authority[atIndex+1:]

		result.User = &Userinfo{}
		if colonIndex := bytes.Index(userinfo, []byte(":")); colonIndex != -1 {
			result.User.username = string(userinfo[:colonIndex])
			result.User.password = string(userinfo[colonIndex+1:])
			result.User.passwordSet = true
		} else {
			result.User.username = string(userinfo)
		}
	}

	// Handle IPv6 addresses
	if bytes.HasPrefix(authority, []byte("[")) {
		closeBracket := bytes.LastIndex(authority, []byte("]"))
		if closeBracket == -1 {
			return nil, ErrInvalidURL
		}

		// Get the IPv6 address part
		result.Host = append([]byte(nil), authority[:closeBracket+1]...)

		// Check for port after the IPv6 address
		if len(authority) > closeBracket+1 {
			if authority[closeBracket+1] == ':' {
				result.Host = append([]byte(nil), authority...) // Include the full authority with port
			}
		}
	} else {
		// Handle IPv4 and regular hostnames
		result.Host = append([]byte(nil), authority...)
	}

	// Parse path, query, and fragment
	if len(remaining) > 0 {
		// Extract fragment
		if hashIndex := bytes.Index(remaining, []byte("#")); hashIndex != -1 {
			result.Fragment = append([]byte(nil), remaining[hashIndex+1:]...)
			remaining = remaining[:hashIndex]
		}

		// Extract query
		if queryIndex := bytes.Index(remaining, []byte("?")); queryIndex != -1 {
			result.Query = append([]byte(nil), remaining[queryIndex+1:]...)
			remaining = remaining[:queryIndex]
		}

		// What's left is the path
		result.Path = append([]byte(nil), remaining...)
	}

	// Build RawRequestURI
	capacity := len(result.Path)
	if len(result.Query) > 0 {
		capacity += 1 + len(result.Query)
	}
	if len(result.Fragment) > 0 {
		capacity += 1 + len(result.Fragment)
	}

	result.RawRequestURI = make([]byte, 0, capacity)
	result.RawRequestURI = append(result.RawRequestURI, result.Path...)
	if len(result.Query) > 0 {
		result.RawRequestURI = append(result.RawRequestURI, '?')
		result.RawRequestURI = append(result.RawRequestURI, result.Query...)
	}
	if len(result.Fragment) > 0 {
		result.RawRequestURI = append(result.RawRequestURI, '#')
		result.RawRequestURI = append(result.RawRequestURI, result.Fragment...)
	}

	return result, nil
}

// Hostname returns the host without port
func (u *RawURLBytes) Hostname() []byte {
	if u.Host == nil {
		return nil
	}

	if i := bytes.LastIndex(u.Host, []byte(":")); i != -1 {
		return u.Host[:i]
	}
	return u.Host
}

// Port returns just the port portion of the host
func (u *RawURLBytes) Port() []byte {
	if u.Host == nil {
		return nil
	}

	if i := bytes.LastIndex(u.Host, []byte(":")); i != -1 {
		return u.Host[i+1:]
	}
	return nil
}

// BaseURL returns scheme://host as []byte
func (u *RawURLBytes) BaseURL() []byte {
	capacity := len(u.Scheme) + 3 + len(u.Host) // scheme:// + host
	result := make([]byte, 0, capacity)
	result = append(result, u.Scheme...)
	result = append(result, []byte("://")...)
	result = append(result, u.Host...)
	return result
}
