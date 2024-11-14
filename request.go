// request.go
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
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

/*
Custom function to send raw requests
Currently working only for HTTP/1.1 requests and partially for HTTP/2 requests
Do not use golang to write pentest tools!
*/
func NewRawRequest(method string, parsedURL *rawurlparser.URL) (*http.Request, error) {
	if method == "" {
		method = "GET"
	}

	// LogDebug("Creating raw request for URL: scheme=%s, host=%s, path=%s, query=%s",
	// 	parsedURL.Scheme, parsedURL.Host, parsedURL.Path, parsedURL.Query)

	// Create URL structure that preserves raw path
	httpURL := &url.URL{
		Scheme:   parsedURL.Scheme,
		Host:     parsedURL.Host,
		Opaque:   "//" + parsedURL.Host + parsedURL.Path,
		RawQuery: parsedURL.Query,
	}

	// Create the request
	req := &http.Request{
		Method: method,
		URL:    httpURL,
		Header: make(http.Header),
		Host:   parsedURL.Host,
	}

	// LogDebug("Created request: method=%s, url=%s, host=%s, opaque=%s, query=%s",
	// 	req.Method, req.URL.String(), req.Host, req.URL.Opaque, req.URL.RawQuery)

	return req, nil
}

func sendRequest(method, rawURL string, headers []Header, bypassMode string) (*ResponseDetails, error) {
	if method == "" {
		method = "GET"
	}

	// Generate canary if debug mode is enabled
	var canary string
	if config.Debug {
		canary = generateRandomString(18)
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
		ForceAttemptHTTP2:     config.ForceHTTP2,
	}

	if config.ParsedProxy != nil {
		transport.Proxy = http.ProxyURL(config.ParsedProxy)
	}

	client := &http.Client{
		Transport: transport,
		// disable redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	//LogDebug("[%s] Parsing URL: %s", bypassMode, rawURL)
	parsedURL := rawurlparser.RawURLParse(rawURL)
	if parsedURL == nil {
		return nil, fmt.Errorf("failed to parse URL")
	}

	//LogDebug("[%s] Creating raw request for: %s with path: %s", bypassMode, rawURL, parsedURL.Path)
	req, err := NewRawRequest(method, parsedURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Close = true

	// Add headers
	for _, header := range headers {
		LogDebug("[%s] Adding header: %s: %s", bypassMode, header.Key, header.Value)
		req.Header.Add(header.Key, header.Value)
	}

	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", defaultUserAgent)
	}

	if config.Debug {
		req.Header.Add("X-Go-Bypass-403", canary)
	}

	// Official logging final
	if config.Debug {
		// If debug mode (-d) include canary
		LogPurple("[%s] [%s] Sending request: %s%s", bypassMode, canary, req.URL, formatHeaders(headers))
	} else if isVerbose {
		// Just verbose (-v)
		LogDebug("[%s] Sending request: %s%s", bypassMode, req.URL, formatHeaders(headers))
	}

	res, err := client.Do(req)
	if err != nil {
		LogError("[%s] Request failed: %v", bypassMode, err)
		return nil, fmt.Errorf("request failed: %v", err)
	}
	//LogDebug("[%s] Got response with status: %d", bypassMode, res.StatusCode)
	defer res.Body.Close()

	respBytes, err := httputil.DumpResponse(res, true)
	if err != nil {
		return nil, fmt.Errorf("failed to dump response: %v", err)
	}

	// Rest of the response handling remains the same
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
