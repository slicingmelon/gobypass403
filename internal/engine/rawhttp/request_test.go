package rawhttp

import (
	"net"
	"testing"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func TestRequestBuilderViaEchoServer(t *testing.T) {
	t.Parallel()

	// Create in-memory listener
	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()

	var (
		echoMethod     string
		echoRequestURI string
		echoHost       string
		echoHeaders    map[string]string
	)

	// Setup test server
	s := &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			echoMethod = string(ctx.Method())
			echoRequestURI = string(ctx.RequestURI())
			echoHost = string(ctx.Host())

			echoHeaders = make(map[string]string)
			ctx.Request.Header.VisitAll(func(key, value []byte) {
				echoHeaders[string(key)] = string(value)
			})
		},
	}
	go s.Serve(ln) //nolint:errcheck

	// Create test client
	client := &Client{
		client: &fasthttp.Client{
			Dial: func(addr string) (net.Conn, error) {
				return ln.Dial()
			},
		},
	}

	builder := &RequestBuilder{client: client}

	// Generate test payloads using actual payload generator
	testURL := "http://example.com/admin/panel"
	jobs := payload.GenerateMidPathsJobs(testURL, "midpaths")

	for _, job := range jobs {
		t.Run(job.PayloadSeed, func(t *testing.T) {
			t.Parallel()

			// Reset captured values
			echoMethod = ""
			echoRequestURI = ""
			echoHost = ""
			echoHeaders = make(map[string]string)

			// Create and send request
			req := fasthttp.AcquireRequest()
			resp := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseRequest(req)
			defer fasthttp.ReleaseResponse(resp)

			builder.BuildRequest(req, job)
			err := client.DoRaw(req, resp)
			if err != nil {
				t.Fatalf("DoRaw failed: %v", err)
			}

			// Verify request details
			if echoRequestURI != job.RawURI {
				t.Errorf("RequestURI = %q, want %q", echoRequestURI, job.RawURI)
			}

			if echoMethod != job.Method {
				t.Errorf("Method = %q, want %q", echoMethod, job.Method)
			}

			// Check Host header handling
			expectedHost := job.Host
			for _, h := range job.Headers {
				if h.Header == "Host" {
					expectedHost = h.Value
					break
				}
			}
			if echoHost != expectedHost {
				t.Errorf("Host = %q, want %q", echoHost, expectedHost)
			}

			// Verify path normalization is disabled
			if req.URI().DisablePathNormalizing != true {
				t.Error("Path normalizing should be disabled")
			}
		})
	}
}
