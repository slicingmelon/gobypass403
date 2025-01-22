package rawhttp

import (
	"bytes"
	"runtime"
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
	curlFlags       = []byte(" -skgi --path-as-is")
	curlMethodX     = []byte(" -X ")
	curlHeaderStart = []byte(" -H '")
	strColonSpace   = []byte(": ")
	strSingleQuote  = []byte("'")
	strSpace        = []byte(" ")
	strCRLF         = []byte("\r\n")
	strHTML         = []byte("html")
)

type ProgressTracker interface {
	UpdateWorkerStats(moduleName string, totalWorkers int64)
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
func BuildHTTPRequest(httpclient *HttpClient, req *fasthttp.Request, job payload.PayloadJob) error {
	//req.Reset()
	req.UseHostHeader = false
	req.Header.SetMethod(job.Method)

	// Set the raw URI for the first line of the request
	req.SetRequestURI(job.FullURL)

	// Disable all normalizing for raw path testing
	req.URI().DisablePathNormalizing = true
	req.Header.DisableNormalizing()
	req.Header.SetNoDefaultContentType(true)

	// !!Always close connection when custom headers are present
	shouldCloseConn := len(job.Headers) > 0 ||
		httpclient.options.DisableKeepAlive ||
		httpclient.options.ProxyURL != ""

	// Set headers directly
	for _, h := range job.Headers {
		if h.Header == "Host" {
			req.UseHostHeader = true
			shouldCloseConn = true
		}
		req.Header.Set(h.Header, h.Value)
	}

	// Set standard headers
	req.Header.SetUserAgentBytes(CustomUserAgent)

	if GB403Logger.IsDebugEnabled() {
		req.Header.Set("X-GB403-Token", job.PayloadToken)
	}

	// Handle connection settings
	if shouldCloseConn {
		req.SetConnectionClose()
	} else {
		//req.Header.Set("Connection", "keep-alive")
		req.SetConnectionClose()
	}

	return nil
}

// ProcessHTTPResponse handles response processing
func ProcessHTTPResponse(httpclient *HttpClient, resp *fasthttp.Response, job payload.PayloadJob) *RawHTTPResponseDetails {
	// Get values that are used multiple times
	statusCode := resp.StatusCode()
	body := resp.Body()
	contentLength := resp.Header.ContentLength()

	result := &RawHTTPResponseDetails{
		URL:           append([]byte(nil), job.FullURL...),
		BypassModule:  append([]byte(nil), job.BypassModule...),
		StatusCode:    statusCode,
		ContentLength: int64(contentLength),
		ResponseBytes: len(body),
	}

	// Check for redirect early
	if fasthttp.StatusCodeIsRedirect(statusCode) {
		if location := PeekHeaderKeyCaseInsensitive(&resp.Header, []byte("Location")); len(location) > 0 {
			result.RedirectURL = append([]byte(nil), location...)
		}
	}

	// Create header buffer
	headerBuf := headerBufPool.Get()
	defer headerBufPool.Put(headerBuf)
	headerBuf.Reset()

	// Write status line
	headerBuf.Write(resp.Header.Protocol())
	headerBuf.Write(strSpace)
	headerBuf.B = fasthttp.AppendUint(headerBuf.B, statusCode)
	headerBuf.Write(strSpace)
	headerBuf.Write(resp.Header.StatusMessage())
	headerBuf.Write(strCRLF)

	// Process headers
	resp.Header.VisitAll(func(key, value []byte) {
		headerBuf.Write(key)
		headerBuf.Write(strColonSpace)
		headerBuf.Write(value)
		headerBuf.Write(strCRLF)
	})
	headerBuf.Write(strCRLF)

	// Store processed data
	result.ResponseHeaders = append([]byte(nil), headerBuf.B...)
	result.ContentType = append([]byte(nil), resp.Header.ContentType()...)
	result.ServerInfo = append([]byte(nil), resp.Header.Server()...)

	// Handle body preview
	if httpclient.options.ResponseBodyPreviewSize > 0 && len(body) > 0 {
		previewSize := httpclient.options.ResponseBodyPreviewSize
		if len(body) > previewSize {
			result.ResponsePreview = append([]byte(nil), body[:previewSize]...)
		} else {
			result.ResponsePreview = append([]byte(nil), body...)
		}
	}

	// Extract title if HTML
	if bytes.Contains(result.ContentType, strHTML) {
		result.Title = extractTitle(body)
	}

	// Generate curl command PoC
	result.CurlCommand = BuildCurlCommandPoc(job)

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
	bb.Write(curlFlags)

	if job.Method != "GET" {
		bb.Write(curlMethodX)
		bb.Write(bytesutil.ToUnsafeBytes(job.Method))
	}

	// Headers
	for _, h := range job.Headers {
		bb.Write(curlHeaderStart)
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
func extractTitle(body []byte) []byte {
	lower := bytes.ToLower(body)
	titleStart := bytes.Index(lower, []byte("<title>"))
	if titleStart == -1 {
		return nil
	}
	titleStart += 7 // len("<title>")

	titleEnd := bytes.Index(lower[titleStart:], []byte("</title>"))
	if titleEnd == -1 {
		return nil
	}

	return append([]byte(nil), body[titleStart:titleStart+titleEnd]...)
}

// match HTTP status code in list
func matchStatusCodes(code int, codes []int) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}
