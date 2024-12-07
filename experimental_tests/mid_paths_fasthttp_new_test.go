package experimentaltests

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/valyala/fasthttp"
)

func TestMidPathsPayloadsFastHTTPNew(t *testing.T) {
	t.Parallel()

	// Generate test jobs
	payloads := util_generateMidPathPayloads(t, []byte("http://localhost:80/test/video.mp4"))

	// Create client with specific options
	client := &fasthttp.Client{
		DisablePathNormalizing:        true,
		DisableHeaderNamesNormalizing: true,
		NoDefaultUserAgentHeader:      true,
	}

	// Process each payload
	for _, payload := range payloads {
		p := payload
		t.Run(string(p.uriPayload), func(t *testing.T) {
			t.Parallel()

			// Generate canary for this request
			canary := make([]byte, 8)
			if _, err := rand.Read(canary); err != nil {
				t.Fatal(err)
			}
			canaryStr := hex.EncodeToString(canary)

			// Build raw request with proper headers and CRLF
			rawReq := bytes.NewBuffer(nil)

			// Request line with raw bytes
			rawReq.Write(p.method)
			rawReq.Write([]byte(" "))
			rawReq.Write(p.uriPayload)
			rawReq.Write([]byte(" HTTP/1.1\r\n"))

			// Required headers
			rawReq.Write([]byte("Host: localhost:80\r\n"))
			rawReq.Write([]byte("Connection: close\r\n"))
			rawReq.Write([]byte(fmt.Sprintf("X-Request-ID: %s\r\n", canaryStr)))
			rawReq.Write([]byte("\r\n")) // Empty line to end headers

			// Calculate MD5s from raw bytes
			requestLine := bytes.TrimRight(bytes.Split(rawReq.Bytes(), []byte("\r\n"))[0], "\r\n")
			expectedReqLineMD5 := fmt.Sprintf("%x", md5.Sum(requestLine))
			expectedPathMD5 := fmt.Sprintf("%x", md5.Sum(p.uriPayload))

			// Log what we're sending (yellow)
			t.Logf("\n%s=== SENDING REQUEST ===%s", Yellow, Reset)
			t.Logf("Raw Request:\n%s", rawReq.String())
			t.Logf("Request-ID: %s", canaryStr)
			t.Logf("Expected Path MD5: %s", expectedPathMD5)
			t.Logf("Expected Request Line MD5: %s", expectedReqLineMD5)
			t.Logf("======================")

			// Send request and get response
			br := bufio.NewReader(bytes.NewReader(rawReq.Bytes()))
			var req fasthttp.Request
			if err := req.Read(br); err != nil {
				t.Errorf("Failed to parse request: %v", err)
				return
			}

			var resp fasthttp.Response
			if err := client.Do(&req, &resp); err != nil {
				t.Errorf("Request failed: %v", err)
				return
			}

			// Verify canary in response
			respCanary := resp.Header.Peek("X-Request-ID")
			if !bytes.Equal([]byte(canaryStr), respCanary) {
				t.Errorf("Canary mismatch. Sent: %s, Got: %s", canaryStr, respCanary)
				return
			}

			// Log what we received (green)
			t.Logf("\n%s=== RECEIVED RESPONSE ===%s", Green, Reset)
			t.Logf("Status: %d", resp.StatusCode())
			t.Logf("Request-ID: %s", respCanary)
			t.Logf("Path MD5: %s", resp.Header.Peek("X-URI-MD5"))
			t.Logf("Request Line MD5: %s", resp.Header.Peek("X-Request-Line-MD5"))
			t.Logf("========================")

			// Compare MD5s
			if !bytes.Equal(resp.Header.Peek("X-URI-MD5"), []byte(expectedPathMD5)) {
				t.Errorf("Path MD5 mismatch. Expected: %s, Got: %s",
					expectedPathMD5, resp.Header.Peek("X-URI-MD5"))
			}
			if !bytes.Equal(resp.Header.Peek("X-Request-Line-MD5"), []byte(expectedReqLineMD5)) {
				t.Errorf("Request Line MD5 mismatch. Expected: %s, Got: %s",
					expectedReqLineMD5, resp.Header.Peek("X-Request-Line-MD5"))
			}
		})
	}
}

// generateMidPathPayloads is a local test helper that generates test payloads
func util_generateMidPathPayloads(t *testing.T, targetURL []byte) []struct {
	method     []byte
	uriPayload []byte
	host       []byte
	payload    []byte
	canary     string
} {
	payloadsPath := filepath.Join("..", "payloads", "internal_midpaths.lst")
	payloads, err := readPayloadsFileBytes(payloadsPath)
	if err != nil {
		t.Fatalf("Failed to read payloads file: %v", err)
	}

	// Parse base URL
	parsedURL, err := RawURLParseBytes(targetURL)
	if err != nil {
		t.Fatalf("Failed to parse baseURL: %v", err)
	}

	// Prepare base path - proper byte handling
	path := parsedURL.Path
	if len(path) == 0 {
		path = []byte("/")
	} else {
		// Make a copy to avoid modifying the original
		path = append([]byte(nil), path...)
	}

	// Count slashes for insertion points
	slashCount := bytes.Count(path, []byte("/"))
	if slashCount == 0 {
		slashCount = 1
	}

	// Track unique payloads
	seen := make(map[string]bool)
	var results []struct {
		method     []byte
		uriPayload []byte
		host       []byte
		payload    []byte
		canary     string
	}

	// Generate variants
	for idxSlash := 0; idxSlash < slashCount; idxSlash++ {
		for _, payload := range payloads {
			// Post-slash variant
			pathPost := ReplaceNthBytes(path, []byte("/"), append([]byte("/"), payload...), idxSlash)
			if !bytes.Equal(pathPost, path) {
				// Basic variant
				if !seen[string(pathPost)] {
					results = append(results, struct {
						method     []byte
						uriPayload []byte
						host       []byte
						payload    []byte
						canary     string
					}{
						method:     []byte("GET"),
						uriPayload: append([]byte(nil), pathPost...),
						host:       []byte(parsedURL.Host),
						payload:    append([]byte(nil), payload...),
						canary:     generateCanaryString(),
					})
					seen[string(pathPost)] = true
				}

				// Double-slash variant
				doubleSlashPath := append([]byte("/"), pathPost...)
				if !seen[string(doubleSlashPath)] {
					results = append(results, struct {
						method     []byte
						uriPayload []byte
						host       []byte
						payload    []byte
						canary     string
					}{
						method:     []byte("GET"),
						uriPayload: doubleSlashPath,
						host:       []byte(parsedURL.Host),
						payload:    append([]byte(nil), payload...),
						canary:     generateCanaryString(),
					})
					seen[string(doubleSlashPath)] = true
				}
			}
		}
	}

	// Debug output
	t.Logf("\n=== Generated %d unique payloads ===", len(results))
	if len(results) > 0 {
		t.Logf("Sample payload: %s", string(results[0].uriPayload))
	}

	return results
}
