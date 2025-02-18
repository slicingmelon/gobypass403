package rawhttp

import (
	"bufio"
	"bytes"
	"io"
	"runtime"
	"sync"
	"unsafe"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/bytesutil"
	GB403Logger "github.com/slicingmelon/go-bypass-403/internal/utils/logger"
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
	curlCmdPool   = &bytesutil.ByteBufferPool{}
	headerBufPool = &bytesutil.ByteBufferPool{}

	// Pre-computed byte slices for static strings
	curlFlags         = []byte("-skgi --path-as-is")
	curlMethodX       = []byte("-X")
	curlHeaderH       = []byte("-H")
	strColonSpace     = []byte(": ")
	strColon          = []byte(":")
	strSingleQuote    = []byte("'")
	strSpace          = []byte(" ")
	strLowerThan      = []byte("<")
	strGreaterThan    = []byte(">")
	strCRLF           = []byte("\r\n")
	strHTML           = []byte("html")
	strTitle          = []byte("<title>")
	strCloseTitle     = []byte("</title>")
	strLocationHeader = []byte("Location")
	strSchemeDelim    = []byte("://")
	strUserAgent      = []byte("User-Agent")

	strErrorReadingPreview = []byte("Error reading reponse preview")
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

var (
	rawRequestBuffPool = sync.Pool{
		New: func() interface{} {
			return bytes.NewBuffer(make([]byte, 0, 4096))
		},
	}
	rawRequestBuffReaderPool = sync.Pool{
		New: func() interface{} {
			return bufio.NewReader(nil)
		},
	}
)

// AcquireRawRequest gets a buffer from the pool
func AcquireRawRequest() *bytes.Buffer {
	return rawRequestBuffPool.Get().(*bytes.Buffer)
}

// ReleaseRawRequest returns a buffer to the pool
func ReleaseRawRequest(buf *bytes.Buffer) {
	buf.Reset()
	rawRequestBuffPool.Put(buf)
}

/*
Crucial information

Client determines the server to be requested in the following order:

  - from RequestURI if it contains full url with scheme and host;
  - from Host header otherwise.

The function doesn't follow redirects. Use Get* for following redirects.
Response is ignored if resp is nil.

The detination/target URL is built based on req.URI, aka where the request will be sent to.

Use req.URI().SetScheme("https") to set the scheme to https
Use req.URI().SetHost("example.com") to set the target host -> this is where the request will be sent to
Use req.SetRequestURI("/path") to set the path (e.g., / or /ssdaf).

For spoofed/custom Host header!
Set req.UseHostHeader = true to ensure the custom Host header is used instead of the URI host (fasthttp will extract it from the URI)
Use req.Header.Set("Host", "evil.com") to set the spoofed Host header

To set true raw request line, e.g. GET @evil.com HTTP/1.1, do not set req.SetRequestURI() and write the raw request line manually.

For this to work, everything must be set in order, Raw Request line, headers, then appply settings,
then set req.UseHostHeader = true and then req.URI().SetScheme() and req.URI().SetHost()
*/
func BuildRawHTTPRequest(httpclient *HTTPClient, req *fasthttp.Request, job payload.PayloadJob) error {
	shouldCloseConn := len(job.Headers) > 0 ||
		httpclient.GetHTTPClientOptions().DisableKeepAlive ||
		httpclient.GetHTTPClientOptions().ProxyURL != ""

	// Get raw request buffer from pool
	buf := AcquireRawRequest()
	defer ReleaseRawRequest(buf)

	// Build request line
	buf.WriteString(job.Method)
	buf.WriteString(" ")
	buf.WriteString(job.RawURI)
	buf.WriteString(" HTTP/1.1") // Add HTTP version
	buf.WriteString("\r\n")      // Important newline after request line

	hasHostHeader := false
	for _, h := range job.Headers {
		if h.Header == "Host" {
			hasHostHeader = true
			shouldCloseConn = true
		}
		buf.WriteString(h.Header)
		buf.WriteString(": ")
		buf.WriteString(h.Value)
		buf.WriteString("\r\n")
	}

	// Add Host header if not present in job.Headers
	if !hasHostHeader {
		buf.WriteString("Host: ")
		buf.WriteString(job.Host)
		buf.WriteString("\r\n")
	}

	buf.WriteString("User-Agent: ") // Note the space after colon
	buf.Write(CustomUserAgent)
	buf.WriteString("\r\n")

	// Debug token
	if GB403Logger.IsDebugEnabled() {
		buf.WriteString("X-GB403-Token: ")
		buf.WriteString(job.PayloadToken)
		buf.WriteString("\r\n")
	}

	// Connection handling
	if shouldCloseConn {
		buf.WriteString("Connection: close\r\n")
	} else {
		buf.WriteString("Connection: keep-alive\r\n")
	}

	// End of headers
	buf.WriteString("\r\n")

	// Parse back into fasthttp.Request
	br := rawRequestBuffReaderPool.Get().(*bufio.Reader)
	br.Reset(bytes.NewReader(buf.Bytes()))
	defer rawRequestBuffReaderPool.Put(br)

	if err := req.ReadLimitBody(br, 0); err != nil {
		GB403Logger.Debug().Msgf("Raw request being parsed:\n%s", buf.String())
		GB403Logger.Error().Msgf("Failed to parse raw request: %v\n", err)
		return err
	}

	// Set URI components after successful parsing
	req.URI().DisablePathNormalizing = true
	req.Header.DisableNormalizing()
	req.Header.SetNoDefaultContentType(true)
	req.UseHostHeader = true
	req.URI().SetScheme(job.Scheme)
	req.URI().SetHost(job.Host)

	return nil
}

func ProcessHTTPResponse(httpclient *HTTPClient, resp *fasthttp.Response, job payload.PayloadJob) *RawHTTPResponseDetails {
	result := AcquireResponseDetails() // Allocate new result each time

	statusCode := resp.StatusCode()
	contentLength := resp.Header.ContentLength()
	httpClientOpts := httpclient.GetHTTPClientOptions()

	// Set basic response details
	result.URL = append(result.URL, job.OriginalURL...)
	result.BypassModule = append(result.BypassModule, job.BypassModule...)
	result.StatusCode = statusCode
	result.ContentLength = int64(contentLength)
	result.DebugToken = append(result.DebugToken, job.PayloadToken...)

	// Check for redirect early
	if fasthttp.StatusCodeIsRedirect(statusCode) {
		if location := PeekResponseHeaderKeyCaseInsensitive(resp, strLocationHeader); len(location) > 0 {
			result.RedirectURL = append(result.RedirectURL, location...)
		}
	}

	// Get all HTTP response headers
	result.ResponseHeaders = GetResponseHeaders(&resp.Header, statusCode, result.ResponseHeaders)

	// Store the rest of the processed data
	result.ContentType = append(result.ContentType, resp.Header.ContentType()...)
	result.ServerInfo = append(result.ServerInfo, resp.Header.Server()...)

	// Handle body preview
	if httpClientOpts.MaxResponseBodySize > 0 && httpClientOpts.ResponseBodyPreviewSize > 0 {
		if httpClientOpts.StreamResponseBody {
			if stream := resp.BodyStream(); stream != nil {
				result.ResponsePreview = ReadLimitedResponseBodyStream(stream, httpClientOpts.ResponseBodyPreviewSize, result.ResponsePreview)
				resp.CloseBodyStream()
				if contentLength > 0 {
					result.ResponseBytes = int(contentLength)
				} else {
					result.ResponseBytes = len(result.ResponsePreview)
				}
			}
		} else {
			if body := resp.Body(); len(body) > 0 {
				previewSize := httpClientOpts.ResponseBodyPreviewSize
				if len(body) > previewSize {
					result.ResponsePreview = append(result.ResponsePreview, body[:previewSize]...)
				} else {
					result.ResponsePreview = append(result.ResponsePreview, body...)
				}

				if contentLength > 0 {
					result.ResponseBytes = int(contentLength)
				} else {
					result.ResponseBytes = len(body)
				}
			}
		}
	}

	// Extract title if HTML response
	if len(result.ResponsePreview) > 0 && bytes.Contains(result.ContentType, strHTML) {
		result.Title = ExtractTitle(result.ResponsePreview, result.Title)
	}

	// Generate curl command PoC
	result.CurlCommand = BuildCurlCommandPoc(job, result.CurlCommand)

	return result
}

// String2Byte converts string to a byte slice without memory allocation.
// This conversion *does not* copy data. Note that casting via "([]byte)(string)" *does* copy data.
// Also note that you *should not* change the byte slice after conversion, because Go strings
// are treated as immutable. This would cause a segmentation violation panic.
func String2Byte(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

// Byte2String converts byte slice to a string without memory allocation.
// This conversion *does not* copy data. Note that casting via "(string)([]byte)" *does* copy data.
// Also note that you *should not* change the byte slice after conversion, because Go strings
// are treated as immutable. This would cause a segmentation violation panic.
func Byte2String(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
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
func BuildCurlCommandPoc(job payload.PayloadJob, dest []byte) []byte {
	// Reset destination slice
	dest = dest[:0]

	// Build command directly into dest
	dest = append(dest, curlCmd...)
	dest = append(dest, strSpace...)
	dest = append(dest, curlFlags...)

	if job.Method != "GET" {
		dest = append(dest, strSpace...)
		dest = append(dest, curlMethodX...)
		dest = append(dest, strSpace...)
		dest = append(dest, bytesutil.ToUnsafeBytes(job.Method)...)
	}

	// Headers
	for _, h := range job.Headers {
		dest = append(dest, strSpace...)
		dest = append(dest, curlHeaderH...)
		dest = append(dest, strSpace...)
		dest = append(dest, strSingleQuote...)
		dest = append(dest, bytesutil.ToUnsafeBytes(h.Header)...)
		dest = append(dest, strColonSpace...)
		dest = append(dest, bytesutil.ToUnsafeBytes(h.Value)...)
		dest = append(dest, strSingleQuote...)
	}

	// URL construction
	dest = append(dest, strSpace...)
	dest = append(dest, strSingleQuote...)

	// Scheme
	dest = append(dest, bytesutil.ToUnsafeBytes(job.Scheme)...)
	dest = append(dest, strSchemeDelim...)

	// Host
	dest = append(dest, bytesutil.ToUnsafeBytes(job.Host)...)

	// RawURI
	dest = append(dest, bytesutil.ToUnsafeBytes(job.RawURI)...)

	dest = append(dest, strSingleQuote...)

	return dest
}

// GetResponseHeaders gets all HTTP headers including values from the response
// Appends them to dest slice
func GetResponseHeaders(h *fasthttp.ResponseHeader, statusCode int, dest []byte) []byte {
	headerBuf := headerBufPool.Get()
	defer headerBufPool.Put(headerBuf)
	headerBuf.Reset()

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

func PeekRequestHeaderKeyCaseInsensitive(h *fasthttp.Request, key []byte) []byte {
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
	// If codes is nil, match all status codes
	if codes == nil {
		return true
	}

	// Otherwise match specific codes
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}
