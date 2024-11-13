// request.go
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
	"time"

	"github.com/slicingmelon/go-rawurlparser"
)

type Header struct {
	Key   string
	Value string
}

type ResponseDetails struct {
	StatusCode      int
	ResponsePreview string // First 200 chars of response body
	ResponseHeaders string
	ContentType     string
	ContentLength   int64  // From Content-Length header
	ServerInfo      string // Server header information
	RedirectURL     string
	ResponseBytes   int // Size of response body only
	Title           string
}

// Helper function to extract title from response body
func extractTitle(body string) string {
	var titleRegex = regexp.MustCompile(`(?i)<title>(.*?)</title>`)

	matches := titleRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func sendRequest(method, url string, headers []Header, bypassMode string) (*ResponseDetails, error) {
	if method == "" {
		method = "GET"
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(config.Timeout) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	if config.ParsedProxy != nil {
		transport.Proxy = http.ProxyURL(config.ParsedProxy)
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	parsedURL := rawurlparser.RawURLParse(url)
	if parsedURL == nil {
		return nil, fmt.Errorf("failed to parse URL")
	}

	req, err := http.NewRequest(method, parsedURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.URL.Opaque = parsedURL.Path
	req.Close = true

	for _, header := range headers {
		req.Header.Add(header.Key, header.Value)
	}

	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", defaultUserAgent)
	}

	if len(headers) > 0 {
		// Build header string
		var headerStrings []string
		for _, h := range headers {
			headerStrings = append(headerStrings, fmt.Sprintf("%s: %s", h.Key, h.Value))
		}
		LogDebug("[%s] Request: %s => Headers: %s",
			bypassMode,
			url,
			strings.Join(headerStrings, ", "))
	} else {
		LogDebug("[%s] Request: %s", bypassMode, url)
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer res.Body.Close()

	respBytes, err := httputil.DumpResponse(res, true)
	if err != nil {
		return nil, fmt.Errorf("failed to dump response: %v", err)
	}

	responseStr := string(respBytes)
	headerEnd := strings.Index(responseStr, "\r\n\r\n")
	body := responseStr[headerEnd+4:]

	// Limit preview to first 200 characters
	bodyPreview := body
	if len(bodyPreview) > 200 {
		bodyPreview = bodyPreview[:200]
	}

	details := &ResponseDetails{
		StatusCode:      res.StatusCode,
		ResponsePreview: bodyPreview,
		ResponseHeaders: responseStr[:headerEnd],
		ContentType:     res.Header.Get("Content-Type"),
		ContentLength:   res.ContentLength,
		ServerInfo:      res.Header.Get("Server"),
		RedirectURL:     res.Header.Get("Location"),
		ResponseBytes:   int(res.ContentLength), // Use Content-Length if available
		Title:           extractTitle(body),
	}

	// If Content-Length header is missing, calculate from body
	if res.ContentLength < 0 {
		details.ResponseBytes = len(body)
	}

	return details, nil
}
