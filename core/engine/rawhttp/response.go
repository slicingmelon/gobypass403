/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package rawhttp

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/bytesutil"
	"github.com/slicingmelon/gobypass403/core/engine/payload"
	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
	"github.com/valyala/fasthttp"
)

func init() {
	// Initialize curl command
	if runtime.GOOS == "windows" {
		curlCmd = []byte("curl.exe")
	} else {
		curlCmd = []byte("curl")
	}
}

var (
	curlCmd []byte

	// Pool for byte buffers
	curlCmdBuffPool    bytesutil.ByteBufferPool
	headerBufPool      bytesutil.ByteBufferPool
	respPreviewBufPool bytesutil.ByteBufferPool

	// Pre-computed byte slices for static strings
	curlFlags   = []byte("-skgi --path-as-is")
	curlMethodX = []byte("-X")
	curlHeaderH = []byte("-H")
	//strColon          = []byte(":")
	strSingleQuote = []byte("'")
	strSpace       = []byte(" ")
	//strLowerThan      = []byte("<")
	//strGreaterThan    = []byte(">")
	strHTML           = []byte("html")
	strTitle          = []byte("<title>")
	strCloseTitle     = []byte("</title>")
	strLocationHeader = []byte("Location")
	strSchemeDelim    = []byte("://")
	//strHostHeader     = []byte("Host")
	//strUserAgent      = []byte("User-Agent")

	strErrorReadingPreview = []byte("Error reading response preview")
)

var responseDetailsPool = sync.Pool{
	New: func() any {
		return &RawHTTPResponseDetails{}
	},
}

type RawHTTPResponseDetails struct {
	URL             []byte
	BypassModule    []byte
	CurlCommand     []byte
	StatusCode      int
	ResponsePreview []byte
	ResponseHeaders []byte
	ContentType     []byte
	ContentLength   int64
	ServerInfo      []byte
	RedirectURL     []byte
	ResponseBytes   int
	Title           []byte
	ResponseTime    int64 // in milliseconds
	DebugToken      []byte
}

func AcquireResponseDetails() *RawHTTPResponseDetails {
	return responseDetailsPool.Get().(*RawHTTPResponseDetails)
}

func ReleaseResponseDetails(rd *RawHTTPResponseDetails) {
	// Clear all byte slices
	rd.URL = rd.URL[:0]
	rd.BypassModule = rd.BypassModule[:0]
	rd.CurlCommand = rd.CurlCommand[:0]
	rd.ResponsePreview = rd.ResponsePreview[:0]
	rd.ResponseHeaders = rd.ResponseHeaders[:0]
	rd.ContentType = rd.ContentType[:0]
	rd.ServerInfo = rd.ServerInfo[:0]
	rd.RedirectURL = rd.RedirectURL[:0]
	rd.Title = rd.Title[:0]
	rd.DebugToken = rd.DebugToken[:0]

	// Reset numeric fields
	rd.StatusCode = 0
	rd.ContentLength = 0
	rd.ResponseBytes = 0
	rd.ResponseTime = 0

	responseDetailsPool.Put(rd)
}

type LimitedWriter struct {
	W io.Writer // Underlying writer
	N int64     // Max bytes remaining
}

func (l *LimitedWriter) Write(p []byte) (n int, err error) {
	if l.N <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > l.N {
		p = p[0:l.N]
	}
	n, err = l.W.Write(p)
	l.N -= int64(n)
	return
}

func ProcessHTTPResponse(httpclient *HTTPClient, resp *fasthttp.Response, bypassPayload payload.BypassPayload) *RawHTTPResponseDetails {
	// Acquire a single result
	result := AcquireResponseDetails()

	// 1. Basic response info
	result.StatusCode = resp.StatusCode()
	result.ContentLength = int64(resp.Header.ContentLength())
	result.URL = append(result.URL, bypassPayload.OriginalURL...)
	result.BypassModule = append(result.BypassModule, bypassPayload.BypassModule...)
	result.DebugToken = append(result.DebugToken, bypassPayload.PayloadToken...)

	// 2. Headers
	result.ResponseHeaders = GetResponseHeaders(&resp.Header, result.StatusCode, result.ResponseHeaders)
	result.ContentType = append(result.ContentType, resp.Header.ContentType()...)
	result.ServerInfo = append(result.ServerInfo, resp.Header.Server()...)

	// 3. Handle redirects
	if fasthttp.StatusCodeIsRedirect(result.StatusCode) {
		if location := PeekResponseHeaderKeyCaseInsensitive(resp, strLocationHeader); len(location) > 0 {
			result.RedirectURL = append(result.RedirectURL, location...)
		}
	}

	// 4. Body preview
	httpClientOpts := httpclient.GetHTTPClientOptions()
	if httpClientOpts.MaxResponseBodySize > 0 && httpClientOpts.ResponseBodyPreviewSize > 0 {
		previewSize := httpClientOpts.ResponseBodyPreviewSize

		buf := respPreviewBufPool.Get()
		defer respPreviewBufPool.Put(buf)

		limitedWriter := &LimitedWriter{
			W: buf,
			N: int64(previewSize),
		}

		// Attempt to write body to the limited writer
		err := resp.BodyWriteTo(limitedWriter)

		// Log only unexpected errors. Ignore nil (success), io.EOF (limit reached),
		// and io.ErrShortWrite (expected when body > previewSize).
		if err != nil && err != io.EOF && !errors.Is(err, io.ErrShortWrite) {
			GB403Logger.Error().Msgf("Unexpected error reading body preview: %v\n", err)
		}

		if len(buf.B) > 0 {
			result.ResponsePreview = append(result.ResponsePreview, buf.B...)
			result.ResponseBytes = len(buf.B)
		}
	}

	// 5. Extract title if HTML
	if len(result.ResponsePreview) > 0 && bytes.Contains(result.ContentType, strHTML) {
		result.Title = ExtractTitle(result.ResponsePreview, result.Title)
	}

	// 6. Build curl command with client options for custom headers
	result.CurlCommand = BuildCurlCommandWithOpts(bypassPayload, httpclient.GetHTTPClientOptions(), result.CurlCommand)

	return result
}

// ReadLimitedResponseBodyStream reads limited bytes from a response body stream
// Appends the result to dest slice
func ReadLimitedResponseBodyStream(stream io.Reader, previewSize int, dest []byte) []byte {
	// Create a buffer for preview
	previewBuf := bytes.NewBuffer(make([]byte, 0, previewSize))

	// Read limited amount of data
	if _, err := io.CopyN(previewBuf, stream, int64(previewSize)); err != nil && err != io.EOF {
		return append(dest[:0], strErrorReadingPreview...)
	}

	return append(dest[:0], previewBuf.Bytes()...)
}

// BuildCurlCommandPoc builds a curl command for the payload job
// Appends the result to dest slice
func BuildCurlCommandPoc(bypassPayload payload.BypassPayload, dest []byte) []byte {
	return BuildCurlCommandWithOpts(bypassPayload, nil, dest)
}

// BuildCurlCommandWithOpts builds a curl command for the payload job with optional client options
// Appends the result to dest slice
func BuildCurlCommandWithOpts(bypassPayload payload.BypassPayload, clientOpts *HTTPClientOptions, dest []byte) []byte {
	cmdBuf := curlCmdBuffPool.Get()
	defer curlCmdBuffPool.Put(cmdBuf)

	// Build command into buffer
	cmdBuf.Write(curlCmd)
	cmdBuf.Write(strSpace)
	cmdBuf.Write(curlFlags)

	if bypassPayload.Method != "GET" {
		cmdBuf.Write(strSpace)
		cmdBuf.Write(curlMethodX)
		cmdBuf.Write(strSpace)
		cmdBuf.Write(bytesutil.ToUnsafeBytes(bypassPayload.Method))
	}

	// Headers from bypassPayload
	for _, h := range bypassPayload.Headers {
		cmdBuf.Write(strSpace)
		cmdBuf.Write(curlHeaderH)
		cmdBuf.Write(strSpace)
		cmdBuf.Write(strSingleQuote)
		cmdBuf.Write(bytesutil.ToUnsafeBytes(h.Header))
		cmdBuf.Write(strColonSpace)
		cmdBuf.Write(bytesutil.ToUnsafeBytes(h.Value))
		cmdBuf.Write(strSingleQuote)
	}

	// Add custom headers from client options
	if clientOpts != nil && len(clientOpts.CustomHTTPHeaders) > 0 {
		for _, header := range clientOpts.CustomHTTPHeaders {
			colonIdx := strings.Index(header, ":")
			if colonIdx != -1 {
				headerName := strings.TrimSpace(header[:colonIdx])
				headerValue := strings.TrimSpace(header[colonIdx+1:])

				cmdBuf.Write(strSpace)
				cmdBuf.Write(curlHeaderH)
				cmdBuf.Write(strSpace)
				cmdBuf.Write(strSingleQuote)
				cmdBuf.Write(bytesutil.ToUnsafeBytes(headerName))
				cmdBuf.Write(strColonSpace)
				cmdBuf.Write(bytesutil.ToUnsafeBytes(headerValue))
				cmdBuf.Write(strSingleQuote)
			}
		}
	}

	// URL construction
	cmdBuf.Write(strSpace)
	cmdBuf.Write(strSingleQuote)

	// Scheme
	cmdBuf.Write(bytesutil.ToUnsafeBytes(bypassPayload.Scheme))
	cmdBuf.Write(strSchemeDelim)

	// Host
	cmdBuf.Write(bytesutil.ToUnsafeBytes(bypassPayload.Host))

	// RawURI
	cmdBuf.Write(bytesutil.ToUnsafeBytes(bypassPayload.RawURI))

	cmdBuf.Write(strSingleQuote)

	// Append to existing slice instead of creating new one
	return append(dest[:0], cmdBuf.B...)
}

// GetResponseHeaders gets all HTTP headers including values from the response
// Appends them to dest slice
func GetResponseHeaders(h *fasthttp.ResponseHeader, statusCode int, dest []byte) []byte {
	headerBuf := headerBufPool.Get()
	defer headerBufPool.Put(headerBuf)

	// Write status line
	headerBuf.Write(h.Protocol())
	headerBuf.Write(strSpace)
	headerBuf.B = fasthttp.AppendUint(headerBuf.B, statusCode)
	headerBuf.Write(strSpace)
	headerBuf.Write(h.StatusMessage())
	headerBuf.Write(strCRLF)

	// Process headers
	h.VisitAll(func(key, value []byte) {
		headerBuf.Write(key)
		headerBuf.Write(strColonSpace)
		headerBuf.Write(value)
		headerBuf.Write(strCRLF)
	})
	headerBuf.Write(strCRLF)

	// Append to existing slice instead of creating new one
	return append(dest[:0], headerBuf.B...)
}

// Helper function to peek a header key case insensitive
func PeekResponseHeaderKeyCaseInsensitive(h *fasthttp.Response, key []byte) []byte {
	var result []byte
	h.Header.VisitAll(func(k, v []byte) {
		if result == nil && bytes.EqualFold(k, key) {
			result = v
		}
	})
	return result
}

// Helper function to extract title from HTML
// Appends the result to dest slice
func ExtractTitle(body []byte, dest []byte) []byte {
	if len(body) == 0 {
		return dest
	}

	// Find start of title tag
	titleStart := bytes.Index(body, strTitle)
	if titleStart == -1 {
		return dest
	}
	titleStart += 7 // len("<title>")

	// Find closing tag
	titleEnd := bytes.Index(body[titleStart:], strCloseTitle)
	if titleEnd == -1 {
		return dest
	}

	// Extract title content
	title := bytes.TrimSpace(body[titleStart : titleStart+titleEnd])
	if len(title) == 0 {
		return dest
	}

	// Append to existing buffer instead of allocating
	return append(dest, title...)
}

// GetHTTPResponseTime returns the response time (in ms) of the HTTP response
func GetHTTPResponseTime(details *RawHTTPResponseDetails) int64 {
	if details == nil {
		return -1
	}
	return details.ResponseTime
}

func matchStatusCodes(code int, codes []int) bool {
	if codes == nil { // Still need explicit nil check
		return true
	}
	return slices.Contains(codes, code)
}
