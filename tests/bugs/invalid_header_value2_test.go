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
		statusCode          int
		contentDisposition  string
		customHeader        string // Format: "Header-Name: value"
		expectedError       bool
		expectedErrorString string
	}{
		{
			name:                "Normal header with spaces in value",
			targetHost:          "localhost",
			targetPath:          "/test/file.png",
			statusCode:          301,
			contentDisposition:  "attachment; filename=\"file with spaces.png\"",
			customHeader:        "",
			expectedError:       false,
			expectedErrorString: "",
		},
		{
			name:                "Header with control character 0x1E",
			targetHost:          "localhost",
			targetPath:          "/test/file.png",
			statusCode:          301,
			contentDisposition:  "attachment; filename=\"file.png\x1e\"",
			customHeader:        "",
			expectedError:       true,
			expectedErrorString: "invalid header",
		},
		{
			name:                "200 OK with custom header containing 0x0A (line feed)",
			targetHost:          "localhost",
			targetPath:          "/test/data.json",
			statusCode:          200,
			contentDisposition:  "",
			customHeader:        "X-Random-Header: aaa\x0abbb",
			expectedError:       true,
			expectedErrorString: "invalid header",
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

						// Build status line based on status code
						var statusLine, responseBody string
						switch tc.statusCode {
						case 200:
							statusLine = "HTTP/1.1 200 OK\r\n"
							responseBody = `{"status":"success","data":"test"}`
						case 301:
							statusLine = "HTTP/1.1 301 Moved Permanently\r\n"
							responseBody = `<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx</center>
</body>
</html>`
						default:
							statusLine = "HTTP/1.1 200 OK\r\n"
							responseBody = `{"status":"ok"}`
						}

						// Build raw HTTP response
						rawResponse := statusLine

						// Add standard headers
						if tc.statusCode == 200 {
							rawResponse += "Content-Type: application/json\r\n"
						} else {
							rawResponse += "Content-Type: application/octet-stream\r\n"
							rawResponse += "Location: https://localhost/test/file.png%1E\r\n"
						}

						// Add Content-Disposition if present
						if tc.contentDisposition != "" {
							rawResponse += "Content-Disposition: " + tc.contentDisposition + "\r\n"
						}

						// Add custom header if present (may contain control characters)
						if tc.customHeader != "" {
							rawResponse += tc.customHeader + "\r\n"
						}

						// Add remaining headers and body
						rawResponse += "Access-Control-Allow-Origin: *\r\n"
						rawResponse += "Access-Control-Allow-Methods: GET,HEAD,OPTIONS\r\n"
						rawResponse += "\r\n"
						rawResponse += responseBody

						_, err = c.Write([]byte(rawResponse))
						if err != nil {
							t.Logf("Write response error: %v", err)
						}
					}(conn)
				}
			}()

			// First capture raw response to see exactly what's being sent
			captureRawResponse2(t, ln, tc.name)

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
					if !strings.Contains(errStr, tc.expectedErrorString) {
						t.Errorf("Expected error to start with %q, got %q", tc.expectedErrorString, errStr)
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
						if len(contentDisp) > 0 {
							fmt.Printf("\n--- Content-Disposition (extracted) ---\n%s\n", string(contentDisp))
						}

						// Extract custom header if test case has one
						if strings.Contains(tc.customHeader, ":") {
							headerName := strings.Split(tc.customHeader, ":")[0]
							customHeaderValue := rawhttp.PeekResponseHeaderKeyCaseInsensitive(resp, []byte(headerName))
							if len(customHeaderValue) > 0 {
								fmt.Printf("\n--- %s (extracted) ---\n%s\n", headerName, string(customHeaderValue))
							}
						}

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
func captureRawResponse2(t *testing.T, ln *fasthttputil.InmemoryListener, testName string) {
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
	fmt.Printf("\n=== Raw HTTP Response for Test: %s ===\n", testName)
	fmt.Println(string(response))

	// Parse and print headers with hex dump
	headersPart := bytes.Split(response, []byte("\r\n\r\n"))[0]
	headerLines := bytes.Split(headersPart, []byte("\r\n"))

	fmt.Println("\n--- All Headers with Hex Dump ---")
	for i, line := range headerLines {
		if len(line) == 0 {
			continue
		}

		// Check if this header contains any control characters
		hasControlChar := false
		for _, b := range line {
			if b < 0x20 && b != 0x09 { // Control characters except TAB
				hasControlChar = true
				break
			}
		}

		if hasControlChar {
			fmt.Printf("\nHeader #%d (contains control character!):\n", i)
		} else {
			fmt.Printf("\nHeader #%d:\n", i)
		}

		fmt.Printf("Text: %s\n", string(line))
		fmt.Print("Hex:  ")
		for _, b := range line {
			fmt.Printf("%02x ", b)
		}
		fmt.Println()
	}

	// Look for specific control characters in the entire response
	controlChars := []struct {
		name string
		char byte
	}{
		{"0x00 (NUL)", 0x00},
		{"0x0A (LF)", 0x0A},
		{"0x0D (CR)", 0x0D},
		{"0x1E (RS)", 0x1E},
	}

	fmt.Println("\n--- Control Character Detection ---")
	for _, ctrl := range controlChars {
		if ctrl.char == 0x0D { // Skip CR as it's expected in HTTP
			continue
		}

		if idx := bytes.IndexByte(response, ctrl.char); idx >= 0 {
			fmt.Printf("Found %s at position %d!\n", ctrl.name, idx)

			// Show context
			context := 15
			start := idx - context
			if start < 0 {
				start = 0
			}
			end := idx + context
			if end > len(response) {
				end = len(response)
			}

			fmt.Printf("Context: %q\n", response[start:end])
			fmt.Print("Hex:     ")
			for _, b := range response[start:end] {
				fmt.Printf("%02x ", b)
			}
			fmt.Println()
		}
	}

	fmt.Println("--- End of Raw Response Debug ---")
}
