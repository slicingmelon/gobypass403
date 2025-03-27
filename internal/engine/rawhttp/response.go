/*
GoByPASS403
Author: slicingmelon <github.com/slicingmelon>
X: x.com/pedro_infosec
*/
package rawhttp

import (
	"bytes"
	"io"
	"runtime"
	"slices"
	"sync"
	"unsafe"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/bytesutil"
	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
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
	curlCmdBuffPool    bytesutil.ByteBufferPool
	headerBufPool      bytesutil.ByteBufferPool
	respPreviewBufPool bytesutil.ByteBufferPool

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
	strHostHeader     = []byte("Host")
	strUserAgent      = []byte("User-Agent")

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

func (r *RawHTTPResponseDetails) CopyTo(dst *RawHTTPResponseDetails) {
	// Copy all byte slices
	dst.URL = append(dst.URL[:0], r.URL...)
	dst.BypassModule = append(dst.BypassModule[:0], r.BypassModule...)
	dst.CurlCommand = append(dst.CurlCommand[:0], r.CurlCommand...)
	dst.ResponseHeaders = append(dst.ResponseHeaders[:0], r.ResponseHeaders...)
	dst.ResponsePreview = append(dst.ResponsePreview[:0], r.ResponsePreview...)
	dst.ContentType = append(dst.ContentType[:0], r.ContentType...)
	dst.ServerInfo = append(dst.ServerInfo[:0], r.ServerInfo...)
	dst.Title = append(dst.Title[:0], r.Title...)
	dst.RedirectURL = append(dst.RedirectURL[:0], r.RedirectURL...)
	dst.DebugToken = append(dst.DebugToken[:0], r.DebugToken...)

	// Copy scalar values
	dst.StatusCode = r.StatusCode
	dst.ContentLength = r.ContentLength
	dst.ResponseBytes = r.ResponseBytes
	dst.ResponseTime = r.ResponseTime
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

		if err := resp.BodyWriteTo(limitedWriter); err != nil && err != io.EOF {
			GB403Logger.Debug().Msgf("Error reading body: %v", err)
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

	// 6. Build curl command
	result.CurlCommand = BuildCurlCommandPoc(bypassPayload, result.CurlCommand)

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
func BuildCurlCommandPoc(bypassPayload payload.BypassPayload, dest []byte) []byte {
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

	// Headers
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
