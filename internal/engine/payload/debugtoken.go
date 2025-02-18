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
func GeneratePayloadToken(job BypassPayload) string {
	bb := &bytesutil.ByteBuffer{}
	bb.B = append(bb.B, 1) // version

	// Add nonce
	bb.B = append(bb.B, 0xFF)
	nonce := make([]byte, 4)
	mu.Lock()
	rnd.Read(nonce)
	mu.Unlock()
	bb.B = append(bb.B, 4)
	bb.Write(nonce)

	// Write Scheme
	if job.Scheme != "" {
		bb.B = append(bb.B, 1) // field type for scheme
		schemeLen := len(job.Scheme)
		bb.B = append(bb.B, byte(schemeLen))
		bb.Write(bytesutil.ToUnsafeBytes(job.Scheme))
	}

	// Write Host
	if job.Host != "" {
		bb.B = append(bb.B, 2) // field type for host
		hostLen := len(job.Host)
		bb.B = append(bb.B, byte(hostLen))
		bb.Write(bytesutil.ToUnsafeBytes(job.Host))
	}

	// Write RawURI
	if job.RawURI != "" {
		bb.B = append(bb.B, 3) // field type for RawURI
		uriLen := len(job.RawURI)
		bb.B = append(bb.B, byte(uriLen))
		bb.Write(bytesutil.ToUnsafeBytes(job.RawURI))
	}

	// Write Method
	if job.Method != "" {
		bb.B = append(bb.B, 4) // field type for method
		methodLen := len(job.Method)
		bb.B = append(bb.B, byte(methodLen))
		bb.Write(bytesutil.ToUnsafeBytes(job.Method))
	}

	// Write Headers if present
	if len(job.Headers) > 0 {
		bb.B = append(bb.B, 5) // field type for headers
		headerCount := len(job.Headers)
		if headerCount > 255 {
			headerCount = 255
		}
		bb.B = append(bb.B, byte(headerCount))
		for _, h := range job.Headers {
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

// DecodePayloadToken
// Use this function to decode a debug token and retrieve back the payload info/URL that was sent
func DecodePayloadToken(token string) (BypassPayload, error) {
	result := BypassPayload{}

	compressed, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return result, fmt.Errorf("failed to decode base64: %w", err)
	}

	bb, err := snappy.Decode(nil, compressed)
	if err != nil {
		return result, fmt.Errorf("failed to decompress: %w", err)
	}

	if len(bb) < 1 {
		return result, fmt.Errorf("invalid token: too short")
	}

	version := bb[0]
	if version != 1 {
		return result, fmt.Errorf("unsupported token version: %d", version)
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
		case 1: // Scheme
			result.Scheme = string(bb[pos : pos+fieldLen])
			pos += fieldLen
		case 2: // Host
			result.Host = string(bb[pos : pos+fieldLen])
			pos += fieldLen
		case 3: // RawURI
			result.RawURI = string(bb[pos : pos+fieldLen])
			pos += fieldLen
		case 4: // Method
			result.Method = string(bb[pos : pos+fieldLen])
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

				result.Headers = append(result.Headers, Headers{
					Header: headerName,
					Value:  headerValue,
				})
			}
		}
	}
	return result, nil
}
