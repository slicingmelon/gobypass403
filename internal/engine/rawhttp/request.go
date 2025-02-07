package rawhttp

import (
	"bytes"
	"fmt"
	"io"
	"runtime"
	"time"
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
)

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
}

// Request must contain at least non-zero RequestURI with full url (including
// scheme and host) or non-zero Host header + RequestURI.
//
// Client determines the server to be requested in the following order:
//
//   - from RequestURI if it contains full url with scheme and host;
//   - from Host header otherwise.
//
// The function doesn't follow redirects. Use Get* for following redirects.
// Response is ignored if resp is nil.
//
// ErrNoFreeConns is returned if all DefaultMaxConnsPerHost connections
// to the requested host are busy.
// BuildRequest creates and configures a HTTP request from a bypass job (payload job)
func BuildHTTPRequest(httpclient *HTTPClient, req *fasthttp.Request, job payload.PayloadJob) error {
	//req.Reset()
	req.UseHostHeader = false
	req.Header.SetMethod(job.Method)

	req.SetRequestURI(job.FullURL)

	// Disable all normalizing for raw path testing
	req.URI().DisablePathNormalizing = true
	req.Header.DisableNormalizing()
	req.Header.SetNoDefaultContentType(true)

	// !!Always close connection when custom headers are present
	shouldCloseConn := len(job.Headers) > 0 ||
		httpclient.GetHTTPClientOptions().DisableKeepAlive ||
		httpclient.GetHTTPClientOptions().ProxyURL != ""

	// Set headers directly
	for _, h := range job.Headers {
		if h.Header == "Host" {
			req.UseHostHeader = true
			shouldCloseConn = true
		}
		req.Header.Set(h.Header, h.Value)
	}

	req.Header.SetUserAgentBytes(CustomUserAgent)

	if GB403Logger.IsDebugEnabled() {
		req.Header.Set("X-GB403-Token", job.PayloadToken)
	}

	// Handle connection settings
	if shouldCloseConn {
		req.SetConnectionClose()
	} else {
		req.Header.Set("Connection", "keep-alive")
		//req.SetConnectionClose()
	}

	return nil
}

// ProcessHTTPResponse handles response processing
func ProcessHTTPResponse(httpclient *HTTPClient, resp *fasthttp.Response, job payload.PayloadJob) *RawHTTPResponseDetails {

	startTime := time.Now()

	statusCode := resp.StatusCode()
	contentLength := resp.Header.ContentLength()

	httpClientOpts := httpclient.GetHTTPClientOptions()

	result := &RawHTTPResponseDetails{
		URL:           append([]byte(nil), job.FullURL...),
		BypassModule:  append([]byte(nil), job.BypassModule...),
		StatusCode:    statusCode,
		ContentLength: int64(contentLength),
	}

	// Check for redirect early
	if fasthttp.StatusCodeIsRedirect(statusCode) {
		if location := PeekHeaderKeyCaseInsensitive(&resp.Header, strLocationHeader); len(location) > 0 {
			result.RedirectURL = append([]byte(nil), location...)
		}
	}

	// Get all HTTP response headers
	result.ResponseHeaders = GetResponseHeaders(&resp.Header, statusCode)

	// Store the rest of the processed data
	result.ContentType = append([]byte(nil), resp.Header.ContentType()...)
	result.ServerInfo = append([]byte(nil), resp.Header.Server()...)

	// Handle body preview
	if httpClientOpts.MaxResponseBodySize > 0 && httpClientOpts.ResponseBodyPreviewSize > 0 {
		if httpClientOpts.StreamResponseBody {
			// Streaming case -> resp.BodyStream and LimitReader
			if stream := resp.BodyStream(); stream != nil {
				previewBuf := make([]byte, httpClientOpts.ResponseBodyPreviewSize)
				limitedReader := io.LimitReader(stream, int64(httpClientOpts.ResponseBodyPreviewSize))
				n, err := limitedReader.Read(previewBuf)
				if err != nil && err != io.EOF {
					result.ResponsePreview = []byte(fmt.Sprintf("Error reading stream: %v", err))
				} else if n > 0 {
					result.ResponsePreview = append([]byte(nil), previewBuf[:n]...)
				}
				resp.CloseBodyStream()

				// For streaming, always use content length from header
				result.ResponseBytes = int(contentLength)
			}
		} else {
			// Non-streaming case -> resp.Body()
			if body := resp.Body(); len(body) > 0 {
				previewSize := httpClientOpts.ResponseBodyPreviewSize
				if len(body) > previewSize {
					result.ResponsePreview = append([]byte(nil), body[:previewSize]...)
				} else {
					result.ResponsePreview = append([]byte(nil), body...)
				}

				// For non-streaming, use content length if available, otherwise use body length
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
		if title := ExtractTitle(result.ResponsePreview); title != nil {
			result.Title = append([]byte(nil), title...)
		}
	}

	// Generate curl command PoC
	result.CurlCommand = BuildCurlCommandPoc(job)

	result.ResponseTime = time.Since(startTime).Milliseconds()

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

// BuildCurlCommandPoc generates a curl poc command to reproduce the findings
func BuildCurlCommandPoc(job payload.PayloadJob) []byte {
	// Get buffer from pool
	bb := curlCmdPool.Get()
	defer curlCmdPool.Put(bb)
	bb.Reset()

	// Build command
	bb.Write(curlCmd)
	bb.Write(strSpace)
	bb.Write(curlFlags)

	if job.Method != "GET" {
		bb.Write(strSpace)
		bb.Write(curlMethodX)
		bb.Write(strSpace)
		bb.Write(bytesutil.ToUnsafeBytes(job.Method))
	}

	// Headers
	for _, h := range job.Headers {
		bb.Write(strSpace)
		bb.Write(curlHeaderH)
		bb.Write(strSpace)
		bb.Write(strSingleQuote)
		bb.Write(bytesutil.ToUnsafeBytes(h.Header))
		bb.Write(strColonSpace)
		bb.Write(bytesutil.ToUnsafeBytes(h.Value))
		bb.Write(strSingleQuote)
	}

	// URL
	bb.Write(strSpace)
	bb.Write(strSingleQuote)
	bb.Write(bytesutil.ToUnsafeBytes(job.FullURL))
	bb.Write(strSingleQuote)

	// Return a copy of the buffer's contents
	return append([]byte(nil), bb.B...)
}

// GetResponseHeaders gets all HTTP headers including values from the response
func GetResponseHeaders(h *fasthttp.ResponseHeader, statusCode int) []byte {
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

	// Return copy of buffer contents
	return append([]byte(nil), headerBuf.B...)
}

// Helper function to peek a header key case insensitive
func PeekHeaderKeyCaseInsensitive(h *fasthttp.ResponseHeader, key []byte) []byte {
	// Try original
	if v := h.PeekBytes(key); len(v) > 0 {
		return v
	}

	// Otherwise lowercase it
	lowerKey := bytes.ToLower(key)
	return h.PeekBytes(lowerKey)
}

// Helper function to extract title from HTML
func ExtractTitle(body []byte) []byte {
	if len(body) == 0 {
		return nil
	}

	// Find start of title tag
	titleStart := bytes.Index(body, strTitle)
	if titleStart == -1 {
		return nil
	}
	titleStart += 7 // len("<title>")

	// Find closing tag
	titleEnd := bytes.Index(body[titleStart:], strCloseTitle)
	if titleEnd == -1 {
		return nil
	}

	// Extract title content
	title := bytes.TrimSpace(body[titleStart : titleStart+titleEnd])
	if len(title) == 0 {
		return nil
	}

	return append([]byte(nil), title...)
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
