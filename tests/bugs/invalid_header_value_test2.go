package tests

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
	"github.com/slicingmelon/gobypass403/core/engine/rawhttp"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func TestInvalidHeaderValue2(t *testing.T) {
	testCases := []struct {
		name                string
		targetHost          string
		targetPath          string
		contentDisposition  string
		expectedError       bool
		expectedErrorPrefix string
	}{
		{
			name:                "Normal header with spaces in value",
			targetHost:          "localhost",
			targetPath:          "/test/file.png",
			contentDisposition:  "attachment; filename=\"file with spaces.png\"",
			expectedError:       false,
			expectedErrorPrefix: "",
		},
		{
			name:                "Header with control character 0x1E",
			targetHost:          "localhost",
			targetPath:          "/test/file.png",
			contentDisposition:  "attachment; filename=\"file.png\x1e\"",
			expectedError:       true,
			expectedErrorPrefix: "error when reading response headers: invalid header value",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ln := fasthttputil.NewInmemoryListener()
			defer ln.Close()

			// Raw HTTP server - writes response bytes directly
			// Handles multiple connections (for captureRawResponse and actual client test)
			go func() {
				for i := 0; i < 2; i++ {
					conn, err := ln.Accept()
					if err != nil {
						t.Logf("Accept error: %v", err)
						return
					}

					go func(c net.Conn) {
						defer c.Close()

						// Read and discard the request
						buf := make([]byte, 4096)
						_, err := c.Read(buf)
						if err != nil {
							t.Logf("Read request error: %v", err)
							return
						}

						// Build raw HTTP response with the specific Content-Disposition header
						rawResponse := "HTTP/1.1 301 Moved Permanently\r\n" +
							"Content-Type: application/octet-stream\r\n" +
							"Location: https://localhost/test/file.png%1E\r\n" +
							"Content-Disposition: " + tc.contentDisposition + "\r\n" +
							"Access-Control-Allow-Origin: *\r\n" +
							"Access-Control-Allow-Methods: GET,HEAD,OPTIONS\r\n" +
							"\r\n" +
							`<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx</center>
</body>
</html>`

						_, err = c.Write([]byte(rawResponse))
						if err != nil {
							t.Logf("Write response error: %v", err)
						}
					}(conn)
				}
			}()

			// First capture raw response to see exactly what's being sent
			captureRawResponse2(t, ln, tc.contentDisposition)

			// Setup rawhttp client with custom dialer
			opts := rawhttp.DefaultHTTPClientOptions()
			opts.Dialer = func(addr string) (net.Conn, error) {
				return ln.Dial()
			}
			client := rawhttp.NewHTTPClient(opts)

			req := fasthttp.AcquireRequest()
			defer fasthttp.ReleaseRequest(req)
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseResponse(resp)

			// Setup payload job
			originalURL := "http://" + tc.targetHost + tc.targetPath
			job := payload.BypassPayload{
				Scheme:      "http",
				Host:        tc.targetHost,
				RawURI:      tc.targetPath,
				Method:      "GET",
				OriginalURL: originalURL,
			}

			// Build raw HTTP request
			err := rawhttp.BuildRawHTTPRequest(client, req, job)
			if err != nil {
				t.Fatalf("Failed to build request: %v", err)
			}

			// Send request
			responseTime, err := client.DoRequest(req, resp, job)

			// Check for the specific error we're trying to reproduce
			if tc.expectedError {
				if err == nil {
					t.Errorf("Expected error but got success")
				} else {
					errStr := err.Error()
					if !strings.HasPrefix(errStr, tc.expectedErrorPrefix) {
						t.Errorf("Expected error to start with %q, got %q", tc.expectedErrorPrefix, errStr)
					} else {
						fmt.Printf("\n✓ Successfully reproduced the error: %v\n", err)
						t.Logf("Successfully reproduced the error: %v", err)
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected success but got error: %v", err)
				} else {
					// Test succeeded - process and print response details
					fmt.Printf("\n✓ Request succeeded for: %s\n", tc.name)
					fmt.Printf("Response time: %d ms\n", responseTime)

					// Process HTTP response using rawhttp's ProcessHTTPResponse
					respDetails := rawhttp.ProcessHTTPResponse(client, resp, job)
					if respDetails != nil {
						fmt.Printf("\n=== Response Details (from rawhttp.ProcessHTTPResponse) ===\n")
						fmt.Printf("URL: %s\n", string(respDetails.URL))
						fmt.Printf("Status Code: %d\n", respDetails.StatusCode)
						fmt.Printf("Content-Type: %s\n", string(respDetails.ContentType))
						fmt.Printf("Content-Length: %d\n", respDetails.ContentLength)
						fmt.Printf("Server Info: %s\n", string(respDetails.ServerInfo))
						fmt.Printf("Response Bytes: %d\n", respDetails.ResponseBytes)
						fmt.Printf("Response Time: %d ms\n", respDetails.ResponseTime)

						if len(respDetails.Title) > 0 {
							fmt.Printf("Title: %s\n", string(respDetails.Title))
						}

						if len(respDetails.RedirectURL) > 0 {
							fmt.Printf("Redirect URL: %s\n", string(respDetails.RedirectURL))
						}

						fmt.Printf("\n--- Response Headers ---\n%s\n", string(respDetails.ResponseHeaders))

						if len(respDetails.ResponsePreview) > 0 {
							fmt.Printf("--- Response Preview ---\n%s\n", string(respDetails.ResponsePreview))
						}

						fmt.Printf("\n--- Curl Command ---\n%s\n", string(respDetails.CurlCommand))

						// Also test individual header extraction
						contentDisp := rawhttp.PeekResponseHeaderKeyCaseInsensitive(resp, []byte("Content-Disposition"))
						fmt.Printf("\n--- Content-Disposition (extracted) ---\n%s\n", string(contentDisp))

						// Release response details
						rawhttp.ReleaseResponseDetails(respDetails)
					}

					t.Logf("Response succeeded - Content-Disposition: %s", resp.Header.Peek("Content-Disposition"))
				}
			}
		})
	}
}

// captureRawResponse2 connects to the server and captures the raw HTTP response for debugging
func captureRawResponse2(t *testing.T, ln *fasthttputil.InmemoryListener, contentDisposition string) {
	conn, err := ln.Dial()
	if err != nil {
		t.Logf("Failed to create raw connection: %v", err)
		return
	}
	defer conn.Close()

	// Send a simple GET request
	_, err = conn.Write([]byte("GET /test/file.png HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	if err != nil {
		t.Logf("Failed to send request: %v", err)
		return
	}

	// Allow some time for the server to process
	time.Sleep(100 * time.Millisecond)

	// Read the response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Logf("Failed to read response: %v", err)
		return
	}

	response := buf[:n]

	// Print response as text
	fmt.Printf("\n--- Raw HTTP Response with Content-Disposition: %s ---\n", contentDisposition)
	fmt.Println(string(response))

	// Print relevant bytes in header value as hex
	headers := bytes.Split(response, []byte("\r\n\r\n"))[0]
	dispositionLine := ""
	for _, line := range bytes.Split(headers, []byte("\r\n")) {
		if bytes.HasPrefix(bytes.ToLower(line), []byte("content-disposition:")) {
			dispositionLine = string(line)
			break
		}
	}

	if dispositionLine != "" {
		fmt.Println("\n--- Content-Disposition Header Bytes ---")
		fmt.Printf("%s\n", dispositionLine)
		fmt.Print("Hex: ")
		for _, b := range []byte(dispositionLine) {
			fmt.Printf("%02x ", b)
		}
		fmt.Println()
	}

	// Look specifically for the 0x1E byte or other control characters if present
	if bytes.IndexByte(response, 0x1E) >= 0 {
		fmt.Println("Found 0x1E byte in the response!")
		pos := bytes.IndexByte(response, 0x1E)
		context := 10 // Show bytes around the position
		start := pos - context
		if start < 0 {
			start = 0
		}
		end := pos + context
		if end > len(response) {
			end = len(response)
		}
		fmt.Printf("Context around 0x1E: %v\n", response[start:end])
	} else {
		fmt.Println("No 0x1E byte found in the response.")
	}
}
