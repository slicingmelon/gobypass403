package tests

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/slicingmelon/gobypass403/core/engine/payload"
	"github.com/slicingmelon/gobypass403/core/engine/rawhttp"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func TestInvalidHeaderValue2(t *testing.T) {
	testCases := []struct {
		name               string
		targetHost         string
		targetPath         string
		statusCode         int
		contentDisposition string
		customHeader       string // Format: "Header-Name: value"
		shouldError        bool
	}{
		{
			name:               "Normal header with spaces in value",
			targetHost:         "localhost",
			targetPath:         "/test/file.png",
			statusCode:         301,
			contentDisposition: "attachment; filename=\"file with spaces.png\"",
			customHeader:       "",
			shouldError:        false,
		},
		{
			name:               "Header with control character 0x1E in value (allowed by patch)",
			targetHost:         "localhost",
			targetPath:         "/test/file.png",
			statusCode:         301,
			contentDisposition: "attachment; filename=\"file.png\x1e\"",
			customHeader:       "",
			shouldError:        true,
		},
		{
			name:               "200 OK with custom header name containing 0x0A (line feed)",
			targetHost:         "localhost",
			targetPath:         "/test/data.json",
			statusCode:         200,
			contentDisposition: "",
			customHeader:       "X-Random\x0aHeader: aaabbb",
			shouldError:        true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ln := fasthttputil.NewInmemoryListener()
			defer ln.Close()

			// Raw HTTP server - writes response bytes directly
			// Handles multiple connections (debug + test + potential retries)
			go func() {
				for {
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

			// Setup rawhttp client with custom dialer and shorter timeout
			opts := rawhttp.DefaultHTTPClientOptions()
			opts.Timeout = 2 * time.Second // Shorter timeout for tests
			opts.DialTimeout = 1 * time.Second
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

			// Print what happened
			fmt.Printf("\n--- Test Result: %s ---\n", tc.name)
			if err != nil {
				fmt.Printf("Error occurred: %v\n", err)
			} else {
				fmt.Printf("Success (Status: %d, Response time: %d ms)\n", resp.StatusCode(), responseTime)
			}

			// Check expectations
			if tc.shouldError && err == nil {
				t.Errorf("Expected error but got success")
			} else if !tc.shouldError && err != nil {
				t.Errorf("Expected success but got error: %v", err)
			} else if err == nil {
				// Test passed and no error - process response details
				respDetails := rawhttp.ProcessHTTPResponse(client, resp, job)
				if respDetails != nil {
					fmt.Printf("\n=== Response Details ===\n")
					fmt.Printf("URL: %s\n", string(respDetails.URL))
					fmt.Printf("Status Code: %d\n", respDetails.StatusCode)
					fmt.Printf("Content-Type: %s\n", string(respDetails.ContentType))
					fmt.Printf("Content-Length: %d\n", respDetails.ContentLength)

					if len(respDetails.Title) > 0 {
						fmt.Printf("Title: %s\n", string(respDetails.Title))
					}

					if len(respDetails.RedirectURL) > 0 {
						fmt.Printf("Redirect URL: %s\n", string(respDetails.RedirectURL))
					}

					fmt.Printf("\n--- Response Headers ---\n%s", string(respDetails.ResponseHeaders))

					if len(respDetails.ResponsePreview) > 0 {
						fmt.Printf("\n--- Response Body ---\n%s\n", string(respDetails.ResponsePreview))
					}

					rawhttp.ReleaseResponseDetails(respDetails)
				}
			}
		})
	}
}

// captureRawResponse2 connects to the server and captures the raw HTTP response for debugging
func captureRawResponse2(t *testing.T, ln *fasthttputil.InmemoryListener, testName string) {
	conn, err := ln.Dial()
	if err != nil {
		t.Logf("Failed to dial: %v", err)
		return
	}
	defer conn.Close()

	// Send GET request
	_, err = conn.Write([]byte("GET /test/file.png HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	if err != nil {
		t.Logf("Failed to send request: %v", err)
		return
	}

	time.Sleep(50 * time.Millisecond)

	// Read response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Logf("Failed to read response: %v", err)
		return
	}

	response := buf[:n]

	fmt.Printf("\n=== Raw Response Debug: %s ===\n", testName)
	fmt.Println(string(response))

	// Check for control characters
	if bytes.IndexByte(response, 0x1E) >= 0 {
		fmt.Println("⚠ Found control char 0x1E in response")
	}
	if bytes.IndexByte(response, 0x0A) >= 0 {
		// LF is in line endings, so check if it's in header value
		headers := bytes.Split(response, []byte("\r\n\r\n"))[0]
		for _, line := range bytes.Split(headers, []byte("\r\n")) {
			if bytes.Contains(line, []byte{0x0A}) {
				fmt.Println("⚠ Found control char 0x0A in header line")
				break
			}
		}
	}
	fmt.Println("--- End Debug ---")
}
