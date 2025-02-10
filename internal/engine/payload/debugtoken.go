package payload

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/bytesutil"
	"github.com/golang/snappy"
)

var (
	// concurrent-safe random source
	rnd = rand.New(rand.NewSource(time.Now().UnixNano()))
	mu  sync.Mutex
)

type SeedData struct {
	OriginalURL  string
	Method       string
	Host         string
	RawURI       string
	Headers      []Headers
	BypassModule string
	FullURL      string
}

// This function will generate a debug token that will act as a fingerprint of the request
// Running in debug mode, a header will be added to each request to debug the requests better
// At any time, a token can be decoded and retrieve back the payload info/URL that was sent
func GenerateDebugToken(data SeedData) string {
	bb := &bytesutil.ByteBuffer{}

	// Write version byte
	bb.B = append(bb.B, 1)

	// Add random nonce
	bb.B = append(bb.B, 0xFF) // special field type for nonce
	nonce := make([]byte, 8)
	mu.Lock()
	rnd.Read(nonce)
	mu.Unlock()
	bb.B = append(bb.B, 8) // nonce length
	bb.Write(nonce)

	// Write FullURL if present
	if data.FullURL != "" {
		bb.B = append(bb.B, 1) // field type
		urlLen := len(data.FullURL)
		if urlLen > 255 {
			urlLen = 255 // truncate long URLs
		}
		bb.B = append(bb.B, byte(urlLen))
		bb.Write(bytesutil.ToUnsafeBytes(data.FullURL[:urlLen]))
	}

	// Write Headers if present
	if len(data.Headers) > 0 {
		bb.B = append(bb.B, 2) // field type
		headerCount := len(data.Headers)
		if headerCount > 255 {
			headerCount = 255 // safety limit
		}
		bb.B = append(bb.B, byte(headerCount))
		for i := 0; i < headerCount; i++ {
			h := data.Headers[i]
			// Write header name
			hLen := len(h.Header)
			if hLen > 255 {
				hLen = 255
			}
			bb.B = append(bb.B, byte(hLen))
			bb.Write(bytesutil.ToUnsafeBytes(h.Header[:hLen]))

			// Write header value
			vLen := len(h.Value)
			if vLen > 255 {
				vLen = 255
			}
			bb.B = append(bb.B, byte(vLen))
			bb.Write(bytesutil.ToUnsafeBytes(h.Value[:vLen]))
		}
	}

	// Compress and encode
	compressed := snappy.Encode(nil, bb.B)
	return base64.RawURLEncoding.EncodeToString(compressed)
}

// Use this function to decode a debug token and retrieve back the payload info/URL that was sent
func DecodeDebugToken(seed string) (SeedData, error) {
	var data SeedData
	// Decode base64
	compressed, err := base64.RawURLEncoding.DecodeString(seed)
	if err != nil {
		return data, fmt.Errorf("failed to decode base64: %w", err)
	}
	// Decompress
	bb, err := snappy.Decode(nil, compressed)
	if err != nil {
		return data, fmt.Errorf("failed to decompress: %w", err)
	}
	// Must be at least 1 byte for version
	if len(bb) < 1 {
		return data, fmt.Errorf("invalid seed: too short")
	}
	// Check version
	version := bb[0]
	if version != 1 {
		return data, fmt.Errorf("unsupported seed version: %d", version)
	}
	// Read fields
	pos := 1
	for pos < len(bb) {
		if pos+2 > len(bb) {
			break // need at least field type and length
		}
		fieldType := bb[pos]
		fieldLen := int(bb[pos+1])
		pos += 2
		if pos+fieldLen > len(bb) {
			break // incomplete field
		}
		switch fieldType {
		case 0xFF: // nonce - just skip it
			pos += fieldLen
		case 1: // FullURL
			data.FullURL = string(bb[pos : pos+fieldLen])
			pos += fieldLen
		case 2: // Headers
			headerCount := fieldLen
			for i := 0; i < headerCount; i++ {
				if pos+2 > len(bb) {
					break
				}
				// Read header name
				nameLen := int(bb[pos])
				pos++
				if pos+nameLen > len(bb) {
					break
				}
				headerName := string(bb[pos : pos+nameLen])
				pos += nameLen
				// Read header value
				if pos+1 > len(bb) {
					break
				}
				valueLen := int(bb[pos])
				pos++
				if pos+valueLen > len(bb) {
					break
				}
				headerValue := string(bb[pos : pos+valueLen])
				pos += valueLen
				data.Headers = append(data.Headers, Headers{
					Header: headerName,
					Value:  headerValue,
				})

			}
		}
	}
	return data, nil
}
