// request.go
package main

import (
	"fmt"
	"io"
	"strings"
	"time"

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
		return nil, fmt.Errorf("failed to parse URL: %v", err)
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

	// Configure options for rawhttp
	options := &rawhttp.Options{
		Timeout:                time.Duration(config.Timeout) * time.Second,
		FollowRedirects:        false,
		MaxRedirects:           0,
		AutomaticHostHeader:    false,
		AutomaticContentLength: true,
		ForceReadAllBody:       true,
	}

	if config.Proxy != "" {
		if !strings.HasPrefix(config.Proxy, "http://") && !strings.HasPrefix(config.Proxy, "https://") {
			config.Proxy = "http://" + config.Proxy
		}
		options.Proxy = config.Proxy
		options.ProxyDialTimeout = 10 * time.Second
	}

	// Create client
	client := rawhttp.NewClient(options)
	defer client.Close()

	// target URL
	target := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// Construct full path with query
	fullPath := parsedURL.Path
	if parsedURL.Query != "" {
		fullPath += "?" + parsedURL.Query
	}

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

	if config.Debug {
		rawBytes, err := rawhttp.DumpRequestRaw(method, target, fullPath, headerMap, nil, options)
		if err != nil {
			LogError("[%s] Failed to dump request: %v", bypassMode, err)
		} else {
			LogPurple("[sendRequest] [%s] Raw request:\n%s", bypassMode, string(rawBytes))
		}
	}

	// Send request using rawhttp
	resp, err := client.DoRaw(method, target, fullPath, headerMap, nil)
	if err != nil {
		if strings.Contains(err.Error(), "proxy") {
			LogError("[%s] Proxy error: %v", bypassMode, err)
		} else if strings.Contains(err.Error(), "tls") {
			LogError("[%s] TLS error: %v", bypassMode, err)
		} else {
			LogError("[%s] Request error: %v", bypassMode, err)
		}
		// Log the request details even on error when verbose
		if isVerbose {
			LogDebug("[%s] Failed request details: %s %s", bypassMode, method, target+fullPath)
		}
		return nil, fmt.Errorf("request failed: %v", err)
	}

	// Read headers and a small preview of response body
	var bodyPreview string
	previewSize := 100 // Limit to 100 bytes

	limitReader := io.LimitReader(resp.Body, int64(previewSize))
	previewBytes, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response preview: %v", err)
	}
	defer resp.Body.Close()

	// Get raw response headers
	var headerBuilder strings.Builder
	err = resp.Header.Write(&headerBuilder)
	if err != nil {
		return nil, fmt.Errorf("failed to get response headers: %v", err)
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
