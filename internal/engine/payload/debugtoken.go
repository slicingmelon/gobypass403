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
	OriginalURL  string // Keep for reference
	Method       string
	Scheme       string // Add separate scheme
	Host         string // Add separate host
	RawURI       string // Add separate RawURI
	Headers      []Headers
	BypassModule string
}

// This function will generate a debug token that will act as a fingerprint of the request
// Running in debug mode, a header will be added to each request to debug the requests better
// At any time, a token can be decoded and retrieve back the payload info/URL that was sent
func GenerateDebugToken(data SeedData) string {
	bb := &bytesutil.ByteBuffer{}
	bb.B = append(bb.B, 1) // version

	// Add nonce
	bb.B = append(bb.B, 0xFF)
	nonce := make([]byte, 8)
	mu.Lock()
	rnd.Read(nonce)
	mu.Unlock()
	bb.B = append(bb.B, 8)
	bb.Write(nonce)

	// Write Method
	if data.Method != "" {
		bb.B = append(bb.B, 1) // field type for method
		methodLen := len(data.Method)
		bb.B = append(bb.B, byte(methodLen))
		bb.Write(bytesutil.ToUnsafeBytes(data.Method))
	}

	// Write Scheme
	if data.Scheme != "" {
		bb.B = append(bb.B, 2) // field type for scheme
		schemeLen := len(data.Scheme)
		bb.B = append(bb.B, byte(schemeLen))
		bb.Write(bytesutil.ToUnsafeBytes(data.Scheme))
	}

	// Write Host
	if data.Host != "" {
		bb.B = append(bb.B, 3) // field type for host
		hostLen := len(data.Host)
		bb.B = append(bb.B, byte(hostLen))
		bb.Write(bytesutil.ToUnsafeBytes(data.Host))
	}

	// Write RawURI
	if data.RawURI != "" {
		bb.B = append(bb.B, 4) // field type for RawURI
		uriLen := len(data.RawURI)
		bb.B = append(bb.B, byte(uriLen))
		bb.Write(bytesutil.ToUnsafeBytes(data.RawURI))
	}

	// Write Headers if present
	if len(data.Headers) > 0 {
		bb.B = append(bb.B, 5) // field type for headers
		headerCount := len(data.Headers)
		if headerCount > 255 {
			headerCount = 255
		}
		bb.B = append(bb.B, byte(headerCount))
		for _, h := range data.Headers {
			hLen := len(h.Header)
			if hLen > 255 {
				hLen = 255
			}
			bb.B = append(bb.B, byte(hLen))
			bb.Write(bytesutil.ToUnsafeBytes(h.Header[:hLen]))

			vLen := len(h.Value)
			if vLen > 255 {
				vLen = 255
			}
			bb.B = append(bb.B, byte(vLen))
			bb.Write(bytesutil.ToUnsafeBytes(h.Value[:vLen]))
		}
	}

	compressed := snappy.Encode(nil, bb.B)
	return base64.RawURLEncoding.EncodeToString(compressed)
}

// Use this function to decode a debug token and retrieve back the payload info/URL that was sent
func DecodeDebugToken(seed string) (SeedData, error) {
	var data SeedData
	compressed, err := base64.RawURLEncoding.DecodeString(seed)
	if err != nil {
		return data, fmt.Errorf("failed to decode base64: %w", err)
	}

	bb, err := snappy.Decode(nil, compressed)
	if err != nil {
		return data, fmt.Errorf("failed to decompress: %w", err)
	}

	if len(bb) < 1 {
		return data, fmt.Errorf("invalid seed: too short")
	}

	version := bb[0]
	if version != 1 {
		return data, fmt.Errorf("unsupported seed version: %d", version)
	}

	pos := 1
	for pos < len(bb) {
		if pos+2 > len(bb) {
			break
		}
		fieldType := bb[pos]
		fieldLen := int(bb[pos+1])
		pos += 2
		if pos+fieldLen > len(bb) {
			break
		}
		switch fieldType {
		case 0xFF: // nonce - skip
			pos += fieldLen
		case 1: // Method
			data.Method = string(bb[pos : pos+fieldLen])
			pos += fieldLen
		case 2: // Scheme
			data.Scheme = string(bb[pos : pos+fieldLen])
			pos += fieldLen
		case 3: // Host
			data.Host = string(bb[pos : pos+fieldLen])
			pos += fieldLen
		case 4: // RawURI
			data.RawURI = string(bb[pos : pos+fieldLen])
			pos += fieldLen
		case 5: // Headers
			headerCount := fieldLen
			for i := 0; i < headerCount; i++ {
				if pos+2 > len(bb) {
					break
				}
				nameLen := int(bb[pos])
				pos++
				if pos+nameLen > len(bb) {
					break
				}
				headerName := string(bb[pos : pos+nameLen])
				pos += nameLen

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
