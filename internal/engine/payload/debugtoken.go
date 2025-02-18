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
/*
Token Structure (before base64 + compression):

[Version][Nonce Block][Scheme Block][Host Block][RawURI Block][Method Block][Headers Block]

1. Version (1 byte):
[0x01]  // Version 1

2. Nonce Block (6 bytes):
[0xFF]  // Nonce identifier
[0x04]  // Length (4 bytes)
[4 random bytes]

3. Scheme Block (variable):
[0x01]  // Scheme identifier
[len]   // Length (1 byte)
[bytes] // Scheme string (e.g., "https")

4. Host Block (variable):
[0x02]  // Host identifier
[len]   // Length (1 byte)
[bytes] // Host string (e.g., "example.com")

5. RawURI Block (variable):
[0x03]  // URI identifier
[len]   // Length (1 byte)
[bytes] // URI string (e.g., "/path")

6. Method Block (variable):
[0x04]  // Method identifier
[len]   // Length (1 byte)
[bytes] // Method string (e.g., "GET")

7. Headers Block (variable):
[0x05]     // Headers identifier
[count]    // Number of headers (1 byte, max 255)
For each header:
  [namelen]  // Header name length (1 byte)
  [name]     // Header name bytes
  [valuelen] // Header value length (1 byte)
  [value]    // Header value bytes

Example (hex):
01                    // Version
FF 04 AB CD EF 12    // Nonce
01 05 68 74 74 70 73 // Scheme "https"
02 0B 65 78 61 6D 70 6C 65 2E 63 6F 6D  // Host "example.com"
03 05 2F 70 61 74 68 // URI "/path"
04 03 47 45 54       // Method "GET"
05 01                // Headers (1 header)
  0A 55 73 65 72 2D 41 67 65 6E 74  // Name "User-Agent"
  07 4D 6F 7A 69 6C 6C 61           // Value "Mozilla"

Final output: base64(snappy(above_bytes))
*/
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
/*
DECODING PROCESS:
================

1. Input: base64 string -> snappy decompress -> byte array
   "aGVsbG8=" -> [compressed] -> [raw bytes]

2. Validation & Initial Read:
   [01]       // Must start with version 1
   pos = 1    // Start reading after version

3. Field Reading Loop (pos < len(bytes)):
   [Field Type][Length][Data...]

   Read 2 bytes minimum:
   - Need 1 byte for type
   - Need 1 byte for length
   If can't read 2 bytes: break

4. Field Processing:

   Type 0xFF (Nonce):
   [FF][04][AB CD EF 12]
    |   |   |
    |   |   +-- Skip these 4 bytes
    |   +------ Length = 4
    +---------- Nonce identifier
   pos += (2 + length)  // Skip nonce

   Type 0x01 (Scheme):
   [01][05][68 74 74 70 73]
    |   |   |
    |   |   +-- "https"
    |   +------ Length = 5
    +---------- Scheme identifier
   result.Scheme = string(data)

   Type 0x02 (Host):
   [02][0B][65 78 61 6D 70 6C 65 2E 63 6F 6D]
    |   |   |
    |   |   +-- "example.com"
    |   +------ Length = 11
    +---------- Host identifier
   result.Host = string(data)

   Type 0x03 (RawURI):
   [03][05][2F 70 61 74 68]
    |   |   |
    |   |   +-- "/path"
    |   +------ Length = 5
    +---------- URI identifier
   result.RawURI = string(data)

   Type 0x04 (Method):
   [04][03][47 45 54]
    |   |   |
    |   |   +-- "GET"
    |   +------ Length = 3
    +---------- Method identifier
   result.Method = string(data)

   Type 0x05 (Headers):
   [05][01]                              // One header
       [0A][55 73 65 72 2D 41 67 65 6E 74]  // "User-Agent" (len=10)
       [07][4D 6F 7A 69 6C 6C 61]           // "Mozilla" (len=7)
    |   |
    |   +-- Number of headers
    +------ Headers identifier

   For each header:
   1. Read name length byte
   2. Read name bytes
   3. Read value length byte
   4. Read value bytes
   5. Append to result.Headers

5. Safety Checks:
   - pos+fieldLen never exceeds total length
   - Break if can't read complete field
   - Maximum 255 headers
   - Maximum 255 bytes per header name/value
*/
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
