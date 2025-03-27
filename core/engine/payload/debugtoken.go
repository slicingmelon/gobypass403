/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package payload

import (
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"math/rand/v2"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/bytesutil"
	"github.com/golang/snappy"
)

var (
	bypassModuleIndex map[string]byte
	methodIndex       map[string]byte
	schemeIndex       = map[string]byte{
		"http":  0,
		"https": 1,
	}
	defaultHTTPMethods = []string{
		"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS",
		"TRACE", "PATCH", "CONNECT",
	}

	once sync.Once
	mu   sync.Mutex
	rnd  = rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), uint64(time.Now().UnixNano())))

	payloadTokenBuff bytesutil.ByteBufferPool
)

func initIndices() {
	once.Do(func() {
		// Initialize bypass module index
		bypassModuleIndex = make(map[string]byte, len(BypassModulesRegistry))
		for i, module := range BypassModulesRegistry {
			bypassModuleIndex[module] = byte(i)
		}

		// Initialize HTTP methods index with fallback defaults
		methods, err := ReadPayloadsFromFile("internal_http_methods.lst")
		if err != nil {
			methods = defaultHTTPMethods
		}
		methodIndex = make(map[string]byte, len(methods))
		for i, method := range methods {
			methodIndex[method] = byte(i)
		}
	})
}

type SeedData struct {
	Method       string
	Scheme       string // Add separate scheme
	Host         string // Add separate host
	RawURI       string // Add separate RawURI
	Headers      []Headers
	Body         string
	BypassModule string
}

// This function will generate a debug token that will act as a fingerprint of the request
// Running in debug mode, a header will be added to each request to debug the requests better
// At any time, a token can be decoded and retrieve back the payload info/URL that was sent
/*
Token Structure (before base64 + compression):

[Version][Nonce Block][Scheme Block][Host Block][RawURI Block][Method Block][Headers Block][BypassModule Block]

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
[idx/bytes] // Either index byte (if standard method) or method string (e.g., "GET")

7. Headers Block (variable):
[0x05]     // Headers identifier
[count]    // Number of headers (1 byte, max 255)
For each header:
  [namelen]  // Header name length (1 byte)
  [name]     // Header name bytes
  [valuelen] // Header value length (1 byte)
  [value]    // Header value bytes

8. BypassModule Block (variable):
[0x06]      // BypassModule identifier
[len]       // Length (1 byte)
[idx/bytes] // Either index byte (if standard module) or module string

Example (hex):
01                    // Version
FF 04 AB CD EF 12    // Nonce
01 05 68 74 74 70 73 // Scheme "https"
02 0B 65 78 61 6D 70 6C 65 2E 63 6F 6D  // Host "example.com"
03 05 2F 70 61 74 68 // URI "/path"
04 01 00             // Method "GET" (indexed)
05 01                // Headers (1 header)
  0A 55 73 65 72 2D 41 67 65 6E 74  // Name "User-Agent"
  07 4D 6F 7A 69 6C 6C 61           // Value "Mozilla"
06 01 03             // BypassModule "http_host" (indexed)

Final output: base64(snappy(above_bytes))
*/
func GeneratePayloadToken(job BypassPayload) string {
	initIndices()

	// Get buffer from pool and ensure it's returned
	bb := payloadTokenBuff.Get()
	defer payloadTokenBuff.Put(bb)

	// version
	bb.B = append(bb.B, 1)

	// Add nonce
	bb.B = append(bb.B, 0xFF, 4)
	nonce := make([]byte, 4)
	mu.Lock()
	for i := range nonce {
		nonce[i] = byte(rnd.Uint32N(256))
	}
	mu.Unlock()
	bb.Write(nonce)

	// Write Scheme using index
	if job.Scheme != "" {
		bb.B = append(bb.B, 1) // field type for scheme
		if idx, ok := schemeIndex[job.Scheme]; ok {
			bb.B = append(bb.B, 1, idx) // length=1, index byte
		} else {
			bb.B = append(bb.B, byte(len(job.Scheme)))
			bb.Write(bytesutil.ToUnsafeBytes(job.Scheme))
		}
	}

	// Write Host
	if job.Host != "" {
		bb.B = append(bb.B, 2) // field type for host
		bb.B = append(bb.B, byte(len(job.Host)))
		bb.Write(bytesutil.ToUnsafeBytes(job.Host))
	}

	// Write RawURI
	if job.RawURI != "" {
		bb.B = append(bb.B, 3) // field type for RawURI
		bb.B = append(bb.B, byte(len(job.RawURI)))
		bb.Write(bytesutil.ToUnsafeBytes(job.RawURI))
	}

	// Write Method using index
	if job.Method != "" {
		bb.B = append(bb.B, 4) // field type for method
		if idx, ok := methodIndex[job.Method]; ok {
			bb.B = append(bb.B, 1, idx) // length=1, index byte
		} else {
			bb.B = append(bb.B, byte(len(job.Method)))
			bb.Write(bytesutil.ToUnsafeBytes(job.Method))
		}
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

	// Write BypassModule using index
	if job.BypassModule != "" {
		bb.B = append(bb.B, 6) // field type for bypass module
		if idx, ok := bypassModuleIndex[job.BypassModule]; ok {
			bb.B = append(bb.B, 1, idx) // length=1, index byte
		} else {
			bb.B = append(bb.B, byte(len(job.BypassModule)))
			bb.Write(bytesutil.ToUnsafeBytes(job.BypassModule))
		}
	}

	// Add Body field - NEW CODE
	if job.Body != "" {
		bb.B = append(bb.B, 7) // field type for body (7)
		bodyLen := len(job.Body)
		if bodyLen > 255 {
			// For bodies larger than 255 bytes, use 2-byte length encoding
			bb.B = append(bb.B, 255, byte(bodyLen>>8), byte(bodyLen&0xFF))
		} else {
			bb.B = append(bb.B, byte(bodyLen))
		}
		bb.Write(bytesutil.ToUnsafeBytes(job.Body))
	}

	// Compress and encode the buffer contents
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

   Type 0x01-0x03 (Scheme, Host, RawURI):
   [01][05][68 74 74 70 73]
    |   |   |
    |   |   +-- String data
    |   +------ Length
    +---------- Field identifier
   result.{Field} = string(data)

   Type 0x04 (Method):
   [04][01][00]
    |   |   |
    |   |   +-- Index (if len=1) or string data
    |   +------ Length = 1 for index, >1 for string
    +---------- Method identifier
   result.Method = lookupMethod(data) or string(data)

   Type 0x05 (Headers):
   [05][01]                              // One header
       [0A][55 73 65 72 2D 41 67 65 6E 74]  // Name "User-Agent" (len=10)
       [07][4D 6F 7A 69 6C 6C 61]           // Value "Mozilla" (len=7)
    |   |
    |   +-- Number of headers
    +------ Headers identifier

   Type 0x06 (BypassModule):
   [06][01][03]
    |   |   |
    |   |   +-- Index (if len=1) or string data
    |   +------ Length = 1 for index, >1 for string
    +---------- BypassModule identifier
   result.BypassModule = lookupModule(data) or string(data)

5. Safety Checks:
   - pos+fieldLen never exceeds total length
   - Break if can't read complete field
   - Maximum 255 headers
   - Maximum 255 bytes per header name/value
   - Indexed lookups fallback to raw strings if not found
*/
func DecodePayloadToken(token string) (BypassPayload, error) {
	initIndices() // Initialize indices if not already done
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
			if fieldLen == 1 {
				// Indexed scheme
				schemeIdx := bb[pos]
				for scheme, idx := range schemeIndex {
					if idx == schemeIdx {
						result.Scheme = scheme
						break
					}
				}
			} else {
				result.Scheme = string(bb[pos : pos+fieldLen])
			}
			pos += fieldLen
		case 2: // Host
			result.Host = string(bb[pos : pos+fieldLen])
			pos += fieldLen
		case 3: // RawURI
			result.RawURI = string(bb[pos : pos+fieldLen])
			pos += fieldLen
		case 4: // Method
			if fieldLen == 1 {
				// Indexed method
				methodIdx := bb[pos]
				for method, idx := range methodIndex {
					if idx == methodIdx {
						result.Method = method
						break
					}
				}
			} else {
				result.Method = string(bb[pos : pos+fieldLen])
			}
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
		case 6: // BypassModule
			if fieldLen == 1 {
				// Indexed bypass module
				moduleIdx := bb[pos]
				if moduleIdx < byte(len(BypassModulesRegistry)) {
					result.BypassModule = BypassModulesRegistry[moduleIdx]
				}
			} else {
				result.BypassModule = string(bb[pos : pos+fieldLen])
			}
			pos += fieldLen

		case 7: // Body - NEW CODE
			if fieldLen == 255 && pos+2 <= len(bb) {
				// Handle large body (length > 255 bytes)
				highByte := int(bb[pos])
				lowByte := int(bb[pos+1])
				actualLen := (highByte << 8) | lowByte
				pos += 2

				if pos+actualLen <= len(bb) {
					result.Body = string(bb[pos : pos+actualLen])
					pos += actualLen
				}
			} else {
				// Normal case
				result.Body = string(bb[pos : pos+fieldLen])
				pos += fieldLen
			}
		}
	}
	return result, nil
}

// GetBypassModuleIndex returns the index of a module in the registry
// Used by debugtoken.go for efficient token generation
func GetBypassModuleIndex(module string) (byte, bool) {
	for i, m := range BypassModulesRegistry {
		if m == module {
			return byte(i), true
		}
	}
	return 0, false
}
