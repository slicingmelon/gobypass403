// request.go
package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/projectdiscovery/rawhttp"
	"github.com/slicingmelon/go-rawurlparser"
)

type Header struct {
	Key   string
	Value string
}

type ResponseDetails struct {
	StatusCode      int
	ResponsePreview string
	ResponseHeaders string
	ContentType     string
	ContentLength   int64
	ServerInfo      string
	RedirectURL     string
	ResponseBytes   int
	Title           string
}

func sendRequest(method, rawURL string, headers []Header, bypassMode string) (*ResponseDetails, error) {
	if method == "" {
		method = "GET"
	}

	parsedURL, err := rawurlparser.RawURLParseWithError(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL %s: %v", rawURL, err)
	}

	LogDebug("[sendRequest] [%s] Parsed URL: scheme=%s, host=%s, path=%s, query=%s\n",
		bypassMode, parsedURL.Scheme, parsedURL.Host, parsedURL.Path, parsedURL.Query)

	// Headers stuff
	var canary string
	headerMap := make(map[string][]string)
	for _, h := range headers {
		headerMap[h.Key] = []string{h.Value}
	}
	if _, exists := headerMap["Host"]; !exists {
		headerMap["Host"] = []string{parsedURL.Host}
	}
	if _, exists := headerMap["User-Agent"]; !exists {
		headerMap["User-Agent"] = []string{defaultUserAgent}
	}
	// Add debug canary
	if config.Debug {
		canary = generateRandomString(18)
		headerMap["X-Go-Bypass-403"] = []string{canary}
	}

	// raw requests boys..
	if _, exists := headerMap["Accept"]; !exists {
		headerMap["Accept"] = []string{"*/*"}
	}
	if _, exists := headerMap["Accept-Encoding"]; !exists {
		headerMap["Accept-Encoding"] = []string{"gzip, deflate, br"}
	}

	// target URL
	target := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// Construct full path with query
	fullPath := parsedURL.Path
	if parsedURL.Query != "" {
		fullPath += "?" + parsedURL.Query
	}

	targetFullURL := target + fullPath

	// Official logging final
	if config.Debug {
		requestLine := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, fullPath)
		LogPurple("[%s] [%s] Sending request: %s [Headers: %s]\n",
			bypassMode,
			canary,
			requestLine,
			formatHeaders(headers))
	} else if isVerbose {
		LogDebug("[%s] Sending request: %s%s [Headers: %s]\n",
			bypassMode,
			target,
			fullPath,
			formatHeaders(headers))
	}

	// Debug logging
	if config.Debug {
		rawBytes, err := rawhttp.DumpRequestRaw(method, target, fullPath, headerMap, nil, globalRawClient.Options)
		if err != nil {
			LogError("[%s] Failed to dump request %s -- Error: %v", bypassMode, targetFullURL, err)
		} else {
			LogPurple("[sendRequest] [%s] Raw request:\n%s", bypassMode, string(rawBytes))
		}
	}

	// Use global client
	resp, err := globalRawClient.DoRawWithOptions(method, target, fullPath, headerMap, nil, globalRawClient.Options)

	if err != nil {
		if strings.Contains(err.Error(), "proxy") {
			LogError("[%s] Proxy error for %s: %v\n", bypassMode, targetFullURL, err)
		} else if strings.Contains(err.Error(), "tls") {
			LogError("[%s] TLS error for %s: %v\n", bypassMode, targetFullURL, err)
		} else {
			LogError("[%s] Request error for %s: %v\n", bypassMode, targetFullURL, err)
		}
		// Log the request details even on error when verbose
		if isVerbose {
			LogDebug("[%s] Failed to send raw request: %s", bypassMode, targetFullURL)
		}
		return nil, fmt.Errorf("[%s] request failed for %s: %v", bypassMode, targetFullURL, err)
	}

	// Read headers and a small preview of response body
	var bodyPreview string
	previewSize := 100 // Limit to 100 bytes

	limitReader := io.LimitReader(resp.Body, int64(previewSize))
	previewBytes, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, fmt.Errorf("[%s] failed to read response preview for %s -- Error: %v", bypassMode, targetFullURL, err)
	}
	defer resp.Body.Close()

	// Get raw response headers
	var headerBuilder strings.Builder
	err = resp.Header.Write(&headerBuilder)
	if err != nil {
		return nil, fmt.Errorf("[%s] failed to get response headers for %s -- Error: %v", bypassMode, targetFullURL, err)
	}

	bodyPreview = string(previewBytes)

	details := &ResponseDetails{
		StatusCode:      resp.StatusCode,
		ResponsePreview: bodyPreview,
		ResponseHeaders: headerBuilder.String(),
		ContentType:     resp.Header.Get("Content-Type"),
		ContentLength:   resp.ContentLength,
		ServerInfo:      resp.Header.Get("Server"),
		RedirectURL:     resp.Header.Get("Location"),
		ResponseBytes:   len(previewBytes),
		Title:           extractTitle(bodyPreview),
	}

	return details, nil
}
