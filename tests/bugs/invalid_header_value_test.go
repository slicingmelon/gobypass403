package tests

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func TestInvalidHeaderValue(t *testing.T) {
	testCases := []struct {
		name                string
		contentDisposition  string
		expectedError       bool
		expectedErrorPrefix string
	}{
		{
			name:                "With literal %1E characters",
			contentDisposition:  "attachment; filename=\"file.png%1E\"",
			expectedError:       false,
			expectedErrorPrefix: "",
		},
		{
			name:                "With actual control character 0x1E",
			contentDisposition:  "attachment; filename=\"file.png\x1e\"",
			expectedError:       true,
			expectedErrorPrefix: "error when reading response headers: invalid header value",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ln := fasthttputil.NewInmemoryListener()
			defer ln.Close()

			go func() {
				err := fasthttp.Serve(ln, func(ctx *fasthttp.RequestCtx) {
					ctx.Response.SetStatusCode(301)
					ctx.Response.Header.Set("Content-Type", "application/octet-stream")
					ctx.Response.Header.Set("Location", "https://localhost/test/file.png%1E")
					ctx.Response.Header.Set("Content-Disposition", tc.contentDisposition)
					ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
					ctx.Response.Header.Set("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS")

					ctx.Write([]byte(`<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx</center>
</body>
</html>`))
				})
				if err != nil {
					t.Logf("fasthttp server error: %v", err)
				}
			}()

			// First capture raw response to see exactly what's being sent
			captureRawResponse(t, ln, tc.contentDisposition)

			// Configure client
			client := &fasthttp.Client{
				StreamResponseBody:            true,
				DisablePathNormalizing:        true,
				DisableHeaderNamesNormalizing: true,
				Dial: func(addr string) (net.Conn, error) {
					return ln.Dial()
				},
			}

			req := fasthttp.AcquireRequest()
			defer fasthttp.ReleaseRequest(req)

			req.SetRequestURI("http://localhost/test/file.png%1E")
			req.Header.SetMethod("GET")

			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseResponse(resp)

			// Send request
			err := client.Do(req, resp)

			// Check for the specific error we're trying to reproduce
			if tc.expectedError {
				if err == nil {
					t.Errorf("Expected error but got success")
				} else {
					errStr := err.Error()
					if !strings.HasPrefix(errStr, tc.expectedErrorPrefix) {
						t.Errorf("Expected error to start with %q, got %q", tc.expectedErrorPrefix, errStr)
					} else {
						fmt.Printf("Successfully reproduced the error: %v\n", err)
						t.Logf("Successfully reproduced the error: %v", err)
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected success but got error: %v", err)
				} else {
					fmt.Printf("Status: %d\n", resp.StatusCode())
					fmt.Printf("Content-Type: %s\n", resp.Header.Peek("Content-Type"))
					fmt.Printf("Content-Disposition: %s\n", resp.Header.Peek("Content-Disposition"))
					t.Logf("Response succeeded - Content-Disposition: %s", resp.Header.Peek("Content-Disposition"))
				}
			}
		})
	}
}

// captureRawResponse connects to the server and captures the raw HTTP response
func captureRawResponse(t *testing.T, ln *fasthttputil.InmemoryListener, contentDisposition string) {
	conn, err := ln.Dial()
	if err != nil {
		t.Logf("Failed to create raw connection: %v", err)
		return
	}
	defer conn.Close()

	// Send a simple GET request
	_, err = conn.Write([]byte("GET /test/file.png%1E HTTP/1.1\r\nHost: localhost\r\n\r\n"))
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

	// Look specifically for the 0x1E byte if present
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

// Helper function to print bytes in a readable format
func printBytes(t *testing.T, prefix string, data []byte) {
	var buf strings.Builder
	buf.WriteString(prefix + " ")

	for i, b := range data {
		if i > 0 && i%16 == 0 {
			buf.WriteString("\n" + prefix + " ")
		}
		buf.WriteString(fmt.Sprintf("%02x ", b))
	}

	t.Log(buf.String())
}
