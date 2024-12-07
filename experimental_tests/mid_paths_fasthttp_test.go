package experimentaltests

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/slicingmelon/go-rawurlparser"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
	"github.com/valyala/fasthttp/fasthttputil"
)

type TestStats struct {
	totalPayloads      int
	successfulRequests int
	mismatchedPaths    sync.Map
	mu                 sync.Mutex
}

type readWriter struct {
	r bytes.Buffer
	w bytes.Buffer
}

func (rw *readWriter) Read(p []byte) (int, error) {
	return rw.r.Read(p)
}

func (rw *readWriter) Write(p []byte) (int, error) {
	return rw.w.Write(p)
}

func (rw *readWriter) Close() error {
	return nil
}

type Header struct {
	Key   []byte
	Value []byte
}

type PayloadJob struct {
	Method     []byte
	Scheme     []byte
	Host       []byte
	Port       []byte
	Path       []byte // The path before the query and fragment -- just for reference
	Query      []byte // The query string -- just for reference - just for reference
	Fragment   []byte // The fragment -- just for reference - just for reference
	URIPayload []byte // Everything after the authority (host:port) -- this will be mosly used
	Headers    []Header
	BypassMode string

	Payload []byte // The raw, original payload that was generated/computed
	Seed    string // randomly generated seed/canary/nonce -- will be useful in the future
}

// GenerateRandomNonce generates a random 12-character string.
func GenerateRandomNonce() string {
	bytes := make([]byte, 6)
	if _, err := rand.Read(bytes); err != nil {
		panic(fmt.Sprintf("Failed to generate nonce: %s", err))
	}
	return hex.EncodeToString(bytes)
}

func startTestServer(t *testing.T, wg *sync.WaitGroup, stats *TestStats) (*fasthttp.Server, *fasthttputil.InmemoryListener) {
	ln := fasthttputil.NewInmemoryListener()

	server := &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			canary := ctx.Request.Header.Peek("X-Debug-Canary")

			// First log the request
			t.Logf("\n%s=== REQUEST [%s] ===%s\n"+
				"%s> Method: %s\n"+
				"> Host: %s\n"+
				"> URI: %s\n"+
				"> Raw Path: %s%s\n",
				Yellow, canary, Reset,
				Yellow,
				ctx.Method(),
				ctx.Host(),
				ctx.RequestURI(),
				ctx.URI().PathOriginal(), Reset)

			// Set response
			ctx.SetStatusCode(fasthttp.StatusOK)
			ctx.Response.Header.Set("X-Test-Path", string(ctx.URI().PathOriginal()))
			ctx.Response.Header.Set("X-Path-Hash", hashRawPath(ctx.URI().PathOriginal()))

			// Then log the response with what was actually set
			t.Logf("\n%s=== RESPONSE [%s] ===%s\n"+
				"%s< Status: %d\n"+
				"< Headers: %s\n"+
				"< Path Hash: %s%s\n",
				Blue, canary, Reset,
				Blue,
				ctx.Response.StatusCode(),
				ctx.Response.Header.String(),
				hashRawPath(ctx.URI().PathOriginal()), Reset)
		},
		DisableHeaderNamesNormalizing: true,
	}

	go func() {
		wg.Done()
		if err := server.Serve(ln); err != nil {
			t.Errorf("Server error: %v", err)
		}
	}()

	return server, ln
}

func hashRawPath(path []byte) string {
	hasher := md5.New()
	hasher.Write(path)
	return hex.EncodeToString(hasher.Sum(nil))
}

// Method to reconstruct the full URL as bytes
func (p *PayloadJob) FullURLBytes() []byte {
	// Pre-calculate capacity to avoid reallocations
	capacity := len(p.Scheme) + 3 + len(p.Host)
	if len(p.Port) > 0 {
		capacity += 1 + len(p.Port)
	}
	capacity += len(p.URIPayload)
	if len(p.Query) > 0 {
		capacity += 1 + len(p.Query)
	}
	if len(p.Fragment) > 0 {
		capacity += 1 + len(p.Fragment)
	}

	b := make([]byte, 0, capacity)
	b = append(b, p.Scheme...)
	b = append(b, []byte("://")...)
	b = append(b, p.Host...)
	if len(p.Port) > 0 {
		b = append(b, ':')
		b = append(b, p.Port...)
	}
	b = append(b, p.URIPayload...)
	if len(p.Query) > 0 {
		b = append(b, '?')
		b = append(b, p.Query...)
	}
	if len(p.Fragment) > 0 {
		b = append(b, '#')
		b = append(b, p.Fragment...)
	}
	return b
}

func (p *PayloadJob) RawPathBytes() []byte {
	// Pre-calculate capacity to avoid reallocations
	capacity := len(p.URIPayload)
	if len(p.Query) > 0 {
		capacity += 1 + len(p.Query) // ?query
	}
	if len(p.Fragment) > 0 {
		capacity += 1 + len(p.Fragment) // #fragment
	}

	b := make([]byte, 0, capacity)
	b = append(b, p.URIPayload...)
	if len(p.Query) > 0 {
		b = append(b, '?')
		b = append(b, p.Query...)
	}
	if len(p.Fragment) > 0 {
		b = append(b, '#')
		b = append(b, p.Fragment...)
	}
	return b
}

// Method to reconstruct the full URL as bytes
func (p *PayloadJob) BuildAbsoluteURLRaw() []byte {
	// Pre-calculate capacity
	capacity := len(p.Scheme) + 3 + len(p.Host) // scheme:// + host
	if len(p.Port) > 0 {
		capacity += 1 + len(p.Port) // :port
	}
	capacity += len(p.URIPayload) // everything else

	b := make([]byte, 0, capacity)
	b = append(b, p.Scheme...)
	b = append(b, []byte("://")...)
	b = append(b, p.Host...)
	if len(p.Port) > 0 {
		b = append(b, ':')
		b = append(b, p.Port...)
	}
	b = append(b, p.URIPayload...)
	return b
}

// Custom function to send and verify raw requests
func sendAndVerifyRawRequest(t *testing.T, client *fasthttp.Client, job PayloadJob, stats *TestStats) {
	rawReq := bytes.NewBuffer(nil)
	rawReq.Write(job.Method)
	rawReq.Write([]byte(" "))
	rawReq.Write(job.URIPayload)
	rawReq.Write([]byte(" HTTP/1.1\r\nHost: "))
	rawReq.Write(job.Host)
	rawReq.Write([]byte("\r\nX-Debug-Canary: "))
	rawReq.Write([]byte(job.Seed))
	rawReq.Write([]byte("\r\n\r\n"))

	t.Logf("\n%s=== REQUEST [%s] ===%s\n%s",
		Yellow, job.Seed, Reset,
		rawReq.String())

	br := bufio.NewReader(rawReq)
	var req fasthttp.Request
	if err := req.Read(br); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp fasthttp.Response
	if err := client.Do(&req, &resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stats.mu.Lock()
	stats.successfulRequests++
	stats.mu.Unlock()
}

func t_generateMidPathsJobs(t *testing.T, baseURL string) []PayloadJob {
	payloadsPath := filepath.Join("..", "payloads", "internal_midpaths.lst")
	if _, err := os.Stat(payloadsPath); os.IsNotExist(err) {
		t.Fatalf("Payloads file does not exist at: %s", payloadsPath)
	}

	payloads, err := readPayloadsFileBytes(payloadsPath)
	if err != nil {
		t.Fatalf("Failed to read payloads file: %v", err)
	}

	parsedURL, err := rawurlparser.RawURLParse(baseURL)
	if err != nil {
		t.Fatalf("Failed to parse baseURL: %v", err)
	}

	baseJob := PayloadJob{
		Method:     []byte("GET"),
		Scheme:     []byte(parsedURL.Scheme),
		Host:       []byte(parsedURL.Host),
		Port:       []byte(parsedURL.Port()),
		URIPayload: []byte(""),
		Headers:    make([]Header, 0),
		BypassMode: "mid_paths",
	}

	path := []byte(parsedURL.Path)
	if len(path) == 0 {
		path = []byte("/")
	}

	slashCount := bytes.Count(path, []byte("/"))
	if slashCount == 0 {
		slashCount = 1
	}

	seen := make(map[string]bool)
	jobs := make([]PayloadJob, 0)

	for idxSlash := 0; idxSlash < slashCount; idxSlash++ {
		for _, payload := range payloads {
			// Post-slash variants (always)
			// Format: /test/{payload}video.mp4
			pathPost := ReplaceNthBytes(path, []byte("/"), append([]byte("/"), payload...), idxSlash)
			if !bytes.Equal(pathPost, path) {
				// Variant 1: scheme://host/test/{payload}video.mp4
				job := baseJob
				job.URIPayload = append([]byte(nil), pathPost...)
				job.Payload = append([]byte(nil), payload...)
				job.Seed = GenerateRandomNonce()
				key := string(job.BuildAbsoluteURLRaw())
				if !seen[key] {
					jobs = append(jobs, job)
					seen[key] = true
				}

				// Variant 2: scheme://host//test/{payload}video.mp4
				job = baseJob
				job.URIPayload = append([]byte("/"), pathPost...)
				job.Payload = append([]byte(nil), payload...)
				job.Seed = GenerateRandomNonce()
				key = string(job.BuildAbsoluteURLRaw())
				if !seen[key] {
					jobs = append(jobs, job)
					seen[key] = true
				}
			}

			// Pre-slash variants (only if idxSlash > 1)
			if idxSlash > 1 {
				// Format: /test{payload}/video.mp4
				pathPre := ReplaceNthBytes(path, []byte("/"), append(payload, []byte("/")...), idxSlash)
				if !bytes.Equal(pathPre, path) {
					// Variant 3: scheme://host/test{payload}/video.mp4
					job := baseJob
					job.URIPayload = append([]byte(nil), pathPre...)
					job.Payload = append([]byte(nil), payload...)
					job.Seed = GenerateRandomNonce()
					key := string(job.BuildAbsoluteURLRaw())
					if !seen[key] {
						jobs = append(jobs, job)
						seen[key] = true
					}

					// Variant 4: scheme://host//test{payload}/video.mp4
					job = baseJob
					job.URIPayload = append([]byte("/"), pathPre...)
					job.Payload = append([]byte(nil), payload...)
					job.Seed = GenerateRandomNonce()
					key = string(job.BuildAbsoluteURLRaw())
					if !seen[key] {
						jobs = append(jobs, job)
						seen[key] = true
					}
				}
			}
		}
	}

	// Debug logging
	t.Logf("\n=== Payload Generation Stats ===")
	t.Logf("Total unique payloads generated: %d", len(jobs))
	t.Logf("Total seen URLs: %d", len(seen))

	t.Logf("\nSample Payloads (first 5):")
	for i, job := range jobs {
		if i >= 5 {
			break
		}
		t.Logf("%d: %s", i+1, string(job.BuildAbsoluteURLRaw()))
	}

	return jobs
}

func printTestSummary(t *testing.T, stats *TestStats) {
	t.Logf("\n%s=== TEST SUMMARY ===%s", Bold, Reset)
	t.Logf("Total Payloads: %d", stats.totalPayloads)
	t.Logf("Successful Requests: %d", stats.successfulRequests)

	var mismatchCount int
	stats.mismatchedPaths.Range(func(key, value interface{}) bool {
		if mismatchCount == 0 {
			t.Logf("\n%sPATH MISMATCHES:%s", Red, Reset)
		}
		mismatchCount++
		info := value.(struct {
			Original string
			Received string
			OrigHash string
			RecvHash string
			Nonce    string
		})
		t.Logf("\n%s[%d] Nonce: %s%s", Yellow, mismatchCount, info.Nonce, Reset)
		t.Logf("Original: %s", info.Original)
		t.Logf("Received: %s", info.Received)
		t.Logf("Original Hash: %s", info.OrigHash)
		t.Logf("Received Hash: %s", info.RecvHash)
		return true
	})

	if mismatchCount > 0 {
		t.Logf("\nTotal Mismatches: %d", mismatchCount)
	}
}

func TestMidPathsPayloads(t *testing.T) {
	stats := &TestStats{}

	inputURL := "http://localhost/video/test.mp4"
	jobs := t_generateMidPathsJobs(t, inputURL)
	stats.totalPayloads = len(jobs)

	var wg sync.WaitGroup
	wg.Add(1)
	server, ln := startTestServer(t, &wg, stats)
	defer server.Shutdown()
	defer ln.Close()

	wg.Wait()

	// In TestMidPathsPayloads function:
	client := &fasthttp.Client{
		// Use fasthttpproxy for HTTP proxy support
		Dial: fasthttpproxy.FasthttpHTTPDialerTimeout("http://127.0.0.1:8080", RequestTimeout),
		// Keep our raw path settings
		DisablePathNormalizing:        true,
		DisableHeaderNamesNormalizing: true,
		NoDefaultUserAgentHeader:      true,
	}

	// Optional: Add proxy control
	const useProxy = true

	// Then in the test:
	if useProxy {
		// Use real HTTP requests through proxy instead of in-memory listener
		ln = nil
	}

	// Send requests using PayloadJob
	for _, job := range jobs {
		sendAndVerifyRawRequest(t, client, job, stats)
	}

	// Print statistics
	t.Logf("\n=== FINAL STATISTICS ===")
	t.Logf("Total Payloads: %s%d%s", Blue, stats.totalPayloads, Reset)
	t.Logf("Successful Requests: %s%d%s", Green, stats.successfulRequests, Reset)
	t.Logf("Failed Requests: %s%d%s", Red, stats.totalPayloads-stats.successfulRequests, Reset)

	// Print mismatched paths for debugging
	pathMismatchCount := 0
	stats.mismatchedPaths.Range(func(key, value interface{}) bool {
		pathMismatchCount++
		t.Logf("\nMismatch [%s]:\n%s", key, value)
		return true
	})

	t.Logf("\nPath Preservation:")
	t.Logf("Paths Preserved: %s%d%s", Green, stats.successfulRequests-pathMismatchCount, Reset)
	t.Logf("Paths Modified: %s%d%s", Red, pathMismatchCount, Reset)

	preservationRate := float64(stats.successfulRequests-pathMismatchCount) / float64(stats.successfulRequests) * 100
	t.Logf("Preservation Rate: %.2f%%", preservationRate)

	// Add assertions
	if stats.successfulRequests == 0 {
		t.Error("No successful requests were made")
	}
	if pathMismatchCount > 0 {
		t.Errorf("Path modifications detected: %d paths were modified", pathMismatchCount)
	}

	printTestSummary(t, stats)
}
