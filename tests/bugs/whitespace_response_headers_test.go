package tests

import (
	"crypto/tls"
	"fmt"
	"testing"

	"github.com/valyala/fasthttp"
)

func TestWhitespaceResponseHeaders(t *testing.T) {
	// Create fasthttp client with specified configuration
	client := &fasthttp.Client{
		StreamResponseBody:            false,
		DisablePathNormalizing:        true,
		DisableHeaderNamesNormalizing: true,

		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxResponseBodySize: 8092 * 2,
		ReadBufferSize:      8092 * 2,
		WriteBufferSize:     8092 * 2,
	}

	// Prepare request
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}()

	req.URI().DisablePathNormalizing = true
	req.Header.DisableNormalizing()
	req.Header.SetNoDefaultContentType(true)

	// Set request URL with special character
	req.SetRequestURI("https://thumbs-cdn.redtube.com/videos/202401/26/447187221/720P_4000K_447187221.mp4%26/")

	// Make the request
	err := client.Do(req, resp)

	// fmt.Printf("Request error: %v\n", err)
	// body := resp.BodyStream()
	// fmt.Printf("Body: %v\n", body)

	if err != nil {
		fmt.Printf("Request error: %v\n", err)

		t.Fail()
	}
}
