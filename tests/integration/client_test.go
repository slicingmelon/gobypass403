package tests

import (
	"testing"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp"
	"github.com/valyala/fasthttp"
)

func TestConsecutiveFailures(t *testing.T) {
	opts := rawhttp.DefaultHTTPClientOptions()
	opts.Timeout = 1000 * time.Millisecond
	opts.MaxRetries = 3
	opts.RetryDelay = 200 * time.Millisecond
	opts.MaxConsecutiveFailedReqs = 5
	opts.BypassModule = "test-mode"

	client := rawhttp.NewHTTPClient(opts)

	// Track stats
	var totalRequests int
	var totalRetries int
	startTime := time.Now()

	// Try just enough requests to hit MaxConsecutiveFailedReqs
	for i := 0; i < 10; i++ {
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()

		defer fasthttp.ReleaseRequest(req)
		defer fasthttp.ReleaseResponse(resp)

		req.SetRequestURI("http://localhost/test")
		req.Header.SetMethod("GET")

		totalRequests++
		start := time.Now()
		_, err := client.DoRequest(req, resp)
		elapsed := time.Since(start)

		if err != nil {
			if err == rawhttp.ErrReqFailedMaxConsecutiveFails {
				t.Logf("Hit max consecutive failures after %d requests in %v", totalRequests, time.Since(startTime))
				t.Logf("Total retries attempted: %d", client.GetPerReqRetryAttempts())
				t.Logf("Current consecutive failures: %d", client.GetConsecutiveFailures())
				return // Test succeeded as expected
			}

			if err == rawhttp.ErrReqFailedMaxRetries {
				totalRetries += int(client.GetPerReqRetryAttempts())
				t.Logf("Request %d failed after retries. Consecutive failures: %d, Total retries: %d, Time: %v",
					totalRequests,
					client.GetConsecutiveFailures(),
					client.GetPerReqRetryAttempts(),
					elapsed)
			}
		}
	}

	t.Errorf("Failed to hit max consecutive failures after %d requests with %d total retries in %v",
		totalRequests, totalRetries, time.Since(startTime))
}
