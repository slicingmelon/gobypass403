package tests

import (
	"crypto/tls"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
)

func TestServerClosedConnectionBeforeReturningTheFirstResponseByte1(t *testing.T) {
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

	req.SetRequestURI("http://localhost/test")

	err := client.Do(req, resp)

	if err == nil {
		t.Fatalf("i expect an error: %v", err)
	}

	fmt.Println(err)
}

/*
go.exe test -timeout 30s -run ^TestServerClosedConnectionBeforeReturningTheFirstResponseByte2$ github.com/slicingmelon/go-bypass-403/tests/bugs -v
=== RUN   TestServerClosedConnectionBeforeReturningTheFirstResponseByte2

	byte_header_error_resp_test.go:88: Success on request 0: 404 <html>
	    <head><title>404 Not Found</title></head>
	    <body>
	    <center><h1>404 Not Found</h1></center>
	    <hr><center>nginx</center>
	    </body>
	    </html>
	byte_header_error_resp_test.go:88: Success on request 1000: 404 <html>
	    <head><title>404 Not Found</title></head>
	    <body>
	    <center><h1>404 Not Found</h1></center>
	    <hr><center>nginx</center>
	    </body>
	    </html>
	byte_header_error_resp_test.go:88: Success on request 2000: 404 <html>
	    <head><title>404 Not Found</title></head>
	    <body>
	    <center><h1>404 Not Found</h1></center>
	    <hr><center>nginx</center>
	    </body>
	    </html>
	byte_header_error_resp_test.go:88: Success on request 3000: 404 <html>
	    <head><title>404 Not Found</title></head>
	    <body>
	    <center><h1>404 Not Found</h1></center>
	    <hr><center>nginx</center>
	    </body>
	    </html>
	byte_header_error_resp_test.go:88: Success on request 4000: 404 <html>
	    <head><title>404 Not Found</title></head>
	    <body>
	    <center><h1>404 Not Found</h1></center>
	    <hr><center>nginx</center>
	    </body>
	    </html>
	byte_header_error_resp_test.go:88: Success on request 5000: 404 <html>
	    <head><title>404 Not Found</title></head>
	    <body>
	    <center><h1>404 Not Found</h1></center>
	    <hr><center>nginx</center>
	    </body>
	    </html>
	byte_header_error_resp_test.go:88: Success on request 6000: 404 <html>
	    <head><title>404 Not Found</title></head>
	    <body>
	    <center><h1>404 Not Found</h1></center>
	    <hr><center>nginx</center>
	    </body>
	    </html>
	byte_header_error_resp_test.go:88: Success on request 7000: 404 <html>
	    <head><title>404 Not Found</title></head>
	    <body>
	    <center><h1>404 Not Found</h1></center>
	    <hr><center>nginx</center>
	    </body>
	    </html>
	byte_header_error_resp_test.go:88: Success on request 8000: 404 <html>
	    <head><title>404 Not Found</title></head>
	    <body>
	    <center><h1>404 Not Found</h1></center>
	    <hr><center>nginx</center>
	    </body>
	    </html>
	byte_header_error_resp_test.go:88: Success on request 9000: 404 <html>
	    <head><title>404 Not Found</title></head>
	    <body>
	    <center><h1>404 Not Found</h1></center>
	    <hr><center>nginx</center>
	    </body>
	    </html>
	byte_header_error_resp_test.go:83: Error on request 9900: the server closed connection before returning the first response byte. Make sure the server returns 'Connection: close' response header before closing the connection
	byte_header_error_resp_test.go:97: Test completed in 8.663774s
	byte_header_error_resp_test.go:98: Total requests: 10000
	byte_header_error_resp_test.go:99: Successful requests: 9937
	byte_header_error_resp_test.go:100: Failed requests: 63
	byte_header_error_resp_test.go:101: Requests per second: 1154.23
	byte_header_error_resp_test.go:104: Errors occurred during the test

--- PASS: TestServerClosedConnectionBeforeReturningTheFirstResponseByte2 (8.66s)
PASS
ok      github.com/slicingmelon/go-bypass-403/tests/bugs        10.506s
*/
func TestServerClosedConnectionBeforeReturningTheFirstResponseByte2(t *testing.T) {
	client := &fasthttp.Client{
		StreamResponseBody:            true,
		DisablePathNormalizing:        true,
		DisableHeaderNamesNormalizing: true,
		MaxConnsPerHost:               768, // 512 + 50% additional (I use the same config on my main tool)
		MaxConnWaitTimeout:            1 * time.Second,
		MaxIdleConnDuration:           1 * time.Minute,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	const totalRequests = 10000    // so a total of 10k requests to be sent
	const concurrentRequests = 512 // and 512 concurrent requests

	var (
		wg           sync.WaitGroup
		errCount     atomic.Int32
		successCount atomic.Int32
		startTime    = time.Now()
		sem          = make(chan struct{}, concurrentRequests)
	)

	for i := 0; i < totalRequests; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(reqNum int) {
			defer func() {
				<-sem
				wg.Done()
			}()
			req := fasthttp.AcquireRequest()
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseRequest(req)
			defer fasthttp.ReleaseResponse(resp)

			req.SetRequestURI(fmt.Sprintf("http://lczen.com/test%d", reqNum)) // Change this to point to your server
			err := client.Do(req, resp)
			if err != nil {
				errCount.Add(1)
				if reqNum%100 == 0 {
					t.Logf("Error on request %d: %v", reqNum, err)
				}
			} else {
				successCount.Add(1)
				if reqNum%1000 == 0 {
					t.Logf("Success on request %d: %d %s", reqNum, resp.StatusCode(), resp.Body())
				}
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(startTime)

	t.Logf("Test completed in %v", elapsed)
	t.Logf("Total requests: %d", totalRequests)
	t.Logf("Successful requests: %d", successCount.Load())
	t.Logf("Failed requests: %d", errCount.Load())
	t.Logf("Requests per second: %.2f", float64(totalRequests)/elapsed.Seconds())

	// most common errors
	if errCount.Load() > 0 {
		t.Logf("Errors occurred during the test")
	}
}
