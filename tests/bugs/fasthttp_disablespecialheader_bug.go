package tests

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/slicingmelon/go-bytesutil/bytesutil"
	"github.com/valyala/fasthttp"
)

var (
	rawRequestBufferPool = bytesutil.ByteBufferPool{}

	rawRequestBuffReaderPool = sync.Pool{
		New: func() any {
			return bufio.NewReader(nil)
		},
	}
)

// Pre-defined byte slices for efficiency (like in the real codebase)
var (
	strSpace          = []byte(" ")
	strCRLF           = []byte("\r\n")
	strColonSpace     = []byte(": ")
	strHTTP11         = []byte("HTTP/1.1")
	strPOST           = []byte("POST")
	strSlash          = []byte("/")
	strHost           = []byte("Host")
	strUserAgent      = []byte("User-Agent")
	strContentType    = []byte("Content-Type")
	strContentLength  = []byte("Content-Length")
	strConnection     = []byte("Connection")
	strClose          = []byte("close")
	strFormURLEncoded = []byte("application/x-www-form-urlencoded")
	strHTTPS          = []byte("https")
)

var (
	testURL   = "https://httpbin.org/anything"
	strPath   = []byte("/anything")
	testHost  = []byte("httpbin.org")
	testBody  = []byte("a=b&test=123")
	userAgent = []byte("fasthttp-test/1.0")
)

func applyReqFlags(req *fasthttp.Request) {
	req.URI().DisablePathNormalizing = true
	req.Header.DisableNormalizing()
	req.Header.SetNoDefaultContentType(true)
	req.UseHostHeader = true
}

// writeRawRequest creates a raw HTTP POST request with body using buffer pool (like the real codebase)
func writeRawRequest() *bytesutil.ByteBuffer {
	// Get ByteBuffer from pool for efficiency
	bb := rawRequestBufferPool.Get()

	// Build request line directly into byte buffer using pre-defined slices
	bb.B = append(bb.B, strPOST...)
	bb.B = append(bb.B, strSpace...)
	bb.B = append(bb.B, strPath...)
	bb.B = append(bb.B, strSpace...)
	bb.B = append(bb.B, strHTTP11...)
	bb.B = append(bb.B, strCRLF...)

	// Add headers using direct byte appends (no string allocations)
	bb.B = append(bb.B, strHost...)
	bb.B = append(bb.B, strColonSpace...)
	bb.B = append(bb.B, testHost...)
	bb.B = append(bb.B, strCRLF...)

	bb.B = append(bb.B, strUserAgent...)
	bb.B = append(bb.B, strColonSpace...)
	bb.B = append(bb.B, userAgent...)
	bb.B = append(bb.B, strCRLF...)

	bb.B = append(bb.B, strContentType...)
	bb.B = append(bb.B, strColonSpace...)
	bb.B = append(bb.B, strFormURLEncoded...)
	bb.B = append(bb.B, strCRLF...)

	bb.B = append(bb.B, strContentLength...)
	bb.B = append(bb.B, strColonSpace...)
	bb.B = append(bb.B, strconv.Itoa(len(testBody))...)
	bb.B = append(bb.B, strCRLF...)

	bb.B = append(bb.B, strConnection...)
	bb.B = append(bb.B, strColonSpace...)
	bb.B = append(bb.B, strClose...)
	bb.B = append(bb.B, strCRLF...)

	// End of headers marker
	bb.B = append(bb.B, strCRLF...)

	// Add body
	bb.B = append(bb.B, testBody...)

	return bb
}

// testWithDisableSpecialHeader demonstrates the bug where body is lost
func testWithDisableSpecialHeader() {
	fmt.Println("=== Testing with DisableSpecialHeader() - DEMONSTRATES BUG ===")

	// Create raw request using buffer pool
	rawReq := writeRawRequest()
	defer rawRequestBufferPool.Put(rawReq) // Return buffer to pool when done
	fmt.Printf("Raw request built:\n%s\n", string(rawReq.B))
	fmt.Println("")

	// Create FastHTTP request
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	applyReqFlags(req)
	req.Header.DisableSpecialHeader() // KEY FACTOR

	// Parse the raw request using pooled bufio.Reader
	br := rawRequestBuffReaderPool.Get().(*bufio.Reader)
	br.Reset(bytes.NewReader(rawReq.B))
	defer rawRequestBuffReaderPool.Put(br)

	if err := req.ReadLimitBody(br, 0); err != nil {
		log.Printf("Error parsing request: %v", err)
		return
	}

	// Set host and scheme again
	req.URI().SetSchemeBytes(strHTTPS)
	req.URI().SetHostBytes(testHost)

	fmt.Printf("\nFastHTTP parsed request body length: %d\n", len(req.Body()))
	fmt.Printf("FastHTTP parsed body content: %q\n", string(req.Body()))

	// Send request
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	client := &fasthttp.Client{
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if err := client.Do(req, resp); err != nil {
		log.Printf("Error sending request: %v", err)
		return
	}

	fmt.Printf("Response status: %d\n", resp.StatusCode())
	fmt.Printf("Response body:\n%s\n\n", string(resp.Body()))
}

// testWithSetBodyRawWorkaround demonstrates the workaround
func testWithSetBodyRawWorkaround() {
	fmt.Println("=== Testing with SetBodyRaw() workaround - WORKS CORRECTLY ===")

	// Create raw request using buffer pool
	rawReq := writeRawRequest()
	defer rawRequestBufferPool.Put(rawReq) // Return buffer to pool when done
	fmt.Printf("Raw request built:\n%s\n", string(rawReq.B))

	// Create FastHTTP request
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	applyReqFlags(req)
	req.Header.DisableSpecialHeader()

	// Parse the raw request using pooled bufio.Reader
	br := rawRequestBuffReaderPool.Get().(*bufio.Reader)
	br.Reset(bytes.NewReader(rawReq.B))
	defer rawRequestBuffReaderPool.Put(br)

	if err := req.ReadLimitBody(br, 0); err != nil {
		log.Printf("Error parsing request: %v", err)
		return
	}

	// WORKAROUND: Manually set the body using SetBodyRaw
	req.SetBodyRaw(testBody)

	req.URI().SetSchemeBytes(strHTTPS)
	req.URI().SetHostBytes(testHost)

	fmt.Printf("\nFastHTTP request body length after SetBodyRaw: %d\n", len(req.Body()))
	fmt.Printf("FastHTTP body content after SetBodyRaw: %q\n", string(req.Body()))

	// Send request
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	client := &fasthttp.Client{
		TLSConfig:           &tls.Config{InsecureSkipVerify: true},
		ReadTimeout:         10 * time.Second,
		WriteTimeout:        10 * time.Second,
		MaxConnDuration:     30 * time.Second,
		MaxIdleConnDuration: 5 * time.Second,
	}

	if err := client.Do(req, resp); err != nil {
		log.Printf("Error sending request: %v", err)
		return
	}

	fmt.Printf("Response status: %d\n", resp.StatusCode())
	fmt.Printf("Response body:\n%s\n\n", string(resp.Body()))
}

// testWithoutDisableSpecialHeader shows normal behavior
func testWithoutDisableSpecialHeader() {
	fmt.Println("=== Testing WITHOUT DisableSpecialHeader() - NORMAL BEHAVIOR ===")

	// Create raw request using buffer pool
	rawReq := writeRawRequest()
	defer rawRequestBufferPool.Put(rawReq) // Return buffer to pool when done
	fmt.Printf("Raw request built:\n%s\n", string(rawReq.B))

	// Create FastHTTP request
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	// DON'T call DisableSpecialHeader - this should work normally
	applyReqFlags(req)

	// Parse the raw request using pooled bufio.Reader
	br := rawRequestBuffReaderPool.Get().(*bufio.Reader)
	br.Reset(bytes.NewReader(rawReq.B))
	defer rawRequestBuffReaderPool.Put(br)

	if err := req.ReadLimitBody(br, 0); err != nil {
		log.Printf("Error parsing request: %v", err)
		return
	}

	req.URI().SetSchemeBytes(strHTTPS)
	req.URI().SetHostBytes(testHost)

	fmt.Printf("\nFastHTTP parsed request body length: %d\n", len(req.Body()))
	fmt.Printf("FastHTTP parsed body content: %q\n", string(req.Body()))

	// Send request
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	client := &fasthttp.Client{
		TLSConfig:           &tls.Config{InsecureSkipVerify: true},
		ReadTimeout:         10 * time.Second,
		WriteTimeout:        10 * time.Second,
		MaxConnDuration:     30 * time.Second,
		MaxIdleConnDuration: 5 * time.Second,
	}

	if err := client.Do(req, resp); err != nil {
		log.Printf("Error sending request: %v", err)
		return
	}

	fmt.Printf("Response status: %d\n", resp.StatusCode())
	fmt.Printf("Response body:\n%s\n\n", string(resp.Body()))
}

func main() {
	fmt.Println("FastHTTP DisableSpecialHeader() Bug Demonstration")
	fmt.Println("=================================================")
	fmt.Printf("Test URL: %s\n", testURL)
	fmt.Printf("Test body: %s\n\n", testBody)

	// Test 1: Show the bug with DisableSpecialHeader
	testWithDisableSpecialHeader()
	time.Sleep(1 * time.Second)

	fmt.Println("=================================================")

	// Test 2: Show the workaround with SetBodyRaw
	testWithSetBodyRawWorkaround()
	time.Sleep(1 * time.Second)

	fmt.Println("=================================================")

	// Test 3: Show normal behavior without DisableSpecialHeader
	testWithoutDisableSpecialHeader()

	fmt.Println("=================================================")

	fmt.Println("BUG SUMMARY:")
	fmt.Println("============")
	fmt.Println("When using req.Header.DisableSpecialHeader(), the request body")
	fmt.Println("gets lost during ReadLimitBody() parsing, even when the raw")
	fmt.Println("request is correctly formatted with Content-Length header.")
	fmt.Println("")
	fmt.Println("WORKAROUND:")
	fmt.Println("After ReadLimitBody(), manually call req.SetBodyRaw(bodyBytes)")
	fmt.Println("to restore the request body.")
	fmt.Println("")
	fmt.Println("EXPECTED BEHAVIOR:")
	fmt.Println("DisableSpecialHeader() should not interfere with body parsing")
	fmt.Println("when the raw request contains a valid Content-Length header.")
}
