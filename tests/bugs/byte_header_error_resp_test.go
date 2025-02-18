package tests

import (
	"crypto/tls"
	"fmt"
	"testing"

	"github.com/valyala/fasthttp"
)

func TestWhitespaceResponseHeaders2(t *testing.T) {
	client := &fasthttp.Client{
		StreamResponseBody:            false,
		DisablePathNormalizing:        true,
		DisableHeaderNamesNormalizing: true,

		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("https://localhost/test")

	err := client.Do(req, resp)

	if err == nil {
		t.Fatalf("i expect an error: %v", err)
	}

	fmt.Println(err)

}
