package tests

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"io"
	"sort"
	"testing"
	"unsafe"

	"github.com/andybalholm/brotli"
	"github.com/golang/snappy"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/slicingmelon/go-bytesutil/bytesutil"
	"github.com/slicingmelon/gobypass403/core/engine/payload"
	"github.com/vmihailenco/msgpack/v5"
)

func TestCompressionComparison(t *testing.T) {
	// Test case with realistic data
	original := payload.SeedData{
		Scheme: "https",
		Host:   "www.example.com",
		RawURI: "/admin",
		Headers: []payload.Headers{{
			Header: "X-AppEngine-Trusted-IP-Request",
			Value:  "1",
		}},
	}

	// Current implementation
	bb := &bytesutil.ByteBuffer{}

	// Write same data format as GeneratePayloadSeed2
	bb.B = append(bb.B, 1)    // version
	bb.B = append(bb.B, 0xFF) // nonce field
	bb.B = append(bb.B, 8)    // nonce length
	bb.Write(make([]byte, 8)) // dummy nonce

	if original.Scheme != "" {
		bb.B = append(bb.B, 1)
		bb.B = append(bb.B, byte(len(original.Scheme)))
		bb.Write(bytesutil.ToUnsafeBytes(original.Scheme))
	}

	if len(original.Headers) > 0 {
		bb.B = append(bb.B, 2)
		bb.B = append(bb.B, byte(len(original.Headers)))
		for _, h := range original.Headers {
			bb.B = append(bb.B, byte(len(h.Header)))
			bb.Write(bytesutil.ToUnsafeBytes(h.Header))
			bb.B = append(bb.B, byte(len(h.Value)))
			bb.Write(bytesutil.ToUnsafeBytes(h.Value))
		}
	}

	// Test Snappy (current)
	snappyCompressed := snappy.Encode(nil, bb.B)
	snappyResult := base64.RawURLEncoding.EncodeToString(snappyCompressed)

	// Test Zlib
	var zlibBuf bytes.Buffer
	zw := zlib.NewWriter(&zlibBuf)
	zw.Write(bb.B)
	zw.Close()
	zlibResult := base64.RawURLEncoding.EncodeToString(zlibBuf.Bytes())

	t.Logf("\nCompression comparison for same payload:")
	t.Logf("Original data length: %d bytes", len(bb.B))
	t.Logf("Snappy compressed length: %d bytes, Base64 length: %d", len(snappyCompressed), len(snappyResult))
	t.Logf("Zlib compressed length: %d bytes, Base64 length: %d", zlibBuf.Len(), len(zlibResult))
	t.Logf("\nSnappy result: %s", snappyResult)
	t.Logf("Zlib result: %s", zlibResult)

	// Verify Zlib roundtrip
	zlibDecoded, err := base64.RawURLEncoding.DecodeString(zlibResult)
	if err != nil {
		t.Fatalf("Failed to decode zlib base64: %v", err)
	}

	zr, err := zlib.NewReader(bytes.NewReader(zlibDecoded))
	if err != nil {
		t.Fatalf("Failed to create zlib reader: %v", err)
	}
	defer zr.Close()

	decompressed, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("Failed to decompress zlib: %v", err)
	}

	// Compare original and decompressed data
	if !bytes.Equal(bb.B, decompressed) {
		t.Error("Zlib roundtrip failed - data mismatch")
	}
}

func TestCompressionComparisonLargePayload(t *testing.T) {
	// Create a larger test case
	original := payload.SeedData{
		Scheme: "https",
		Host:   "www.example.com",
		RawURI: "/admin/dashboard/users/settings",
		Headers: []payload.Headers{
			{Header: "X-AppEngine-Trusted-IP-Request", Value: "1"},

			{Header: "X-Forwarded-For", Value: "127.0.0.1"},
			{Header: "X-Original-URL", Value: "/admin/dashboard"},
			{Header: "X-Rewrite-URL", Value: "/admin/dashboard"},
			{Header: "X-Custom-Header", Value: "some-long-value-that-needs-compression"},
		},
	}

	bb := &bytesutil.ByteBuffer{}

	// Write data
	bb.B = append(bb.B, 1)
	bb.B = append(bb.B, 0xFF)
	bb.B = append(bb.B, 8)
	bb.Write(make([]byte, 8))

	if original.Scheme != "" {
		bb.B = append(bb.B, 1)
		bb.B = append(bb.B, byte(len(original.Scheme)))
		bb.Write(bytesutil.ToUnsafeBytes(original.Scheme))
	}

	if len(original.Headers) > 0 {
		bb.B = append(bb.B, 2)
		bb.B = append(bb.B, byte(len(original.Headers)))
		for _, h := range original.Headers {
			bb.B = append(bb.B, byte(len(h.Header)))
			bb.Write(bytesutil.ToUnsafeBytes(h.Header))
			bb.B = append(bb.B, byte(len(h.Value)))
			bb.Write(bytesutil.ToUnsafeBytes(h.Value))
		}
	}

	// Test both compressions
	snappyCompressed := snappy.Encode(nil, bb.B)
	snappyResult := base64.RawURLEncoding.EncodeToString(snappyCompressed)

	var zlibBuf bytes.Buffer
	zw := zlib.NewWriter(&zlibBuf)
	zw.Write(bb.B)
	zw.Close()
	zlibResult := base64.RawURLEncoding.EncodeToString(zlibBuf.Bytes())

	t.Logf("\nLarge payload compression comparison:")
	t.Logf("Original data length: %d bytes", len(bb.B))
	t.Logf("Snappy compressed length: %d bytes, Base64 length: %d", len(snappyCompressed), len(snappyResult))
	t.Logf("Zlib compressed length: %d bytes, Base64 length: %d", zlibBuf.Len(), len(zlibResult))
	t.Logf("\nSnappy result: %s", snappyResult)
	t.Logf("Zlib result: %s", zlibResult)
}

func TestAdvancedCompressionComparison(t *testing.T) {
	original := payload.SeedData{
		Scheme: "https",
		Host:   "www.example.com",
		RawURI: "/admin/dashboard/users/settings",
		Headers: []payload.Headers{
			{Header: "X-AppEngine-Trusted-IP-Request", Value: "1"},

			{Header: "X-Forwarded-For", Value: "127.0.0.1, 10.0.0.1, 192.168.1.1"},
			{Header: "X-Original-URL", Value: "/admin/dashboard/users/settings"},
			{Header: "X-Rewrite-URL", Value: "/admin/dashboard/users/settings"},
			{Header: "X-Custom-Header", Value: "some-long-value-that-needs-compression-and-repeats-some-long-value"},
			{Header: "X-Custom-Header2", Value: "some-long-value-that-needs-compression-and-repeats-some-long-value"},
		},
	}

	bb := &bytesutil.ByteBuffer{}

	// Write data
	bb.B = append(bb.B, 1)
	bb.B = append(bb.B, 0xFF)
	bb.B = append(bb.B, 4) // reduced nonce size
	bb.Write(make([]byte, 4))

	if original.Scheme != "" {
		bb.B = append(bb.B, 1)
		bb.B = append(bb.B, byte(len(original.Scheme)))
		bb.Write(bytesutil.ToUnsafeBytes(original.Scheme))
	}

	if len(original.Headers) > 0 {
		bb.B = append(bb.B, 2)
		bb.B = append(bb.B, byte(len(original.Headers)))
		for _, h := range original.Headers {
			bb.B = append(bb.B, byte(len(h.Header)))
			bb.Write(bytesutil.ToUnsafeBytes(h.Header))
			bb.B = append(bb.B, byte(len(h.Value)))
			bb.Write(bytesutil.ToUnsafeBytes(h.Value))
		}
	}

	originalData := bb.B

	// Test all compression methods
	results := make(map[string]string)
	sizes := make(map[string]int)

	// 1. Snappy (current)
	snappyCompressed := snappy.Encode(nil, originalData)
	results["Snappy"] = base64.RawURLEncoding.EncodeToString(snappyCompressed)
	sizes["Snappy"] = len(snappyCompressed)

	// 2. Zlib
	var zlibBuf bytes.Buffer
	zw := zlib.NewWriter(&zlibBuf)
	zw.Write(originalData)
	zw.Close()
	results["Zlib"] = base64.RawURLEncoding.EncodeToString(zlibBuf.Bytes())
	sizes["Zlib"] = zlibBuf.Len()

	// 3. Zstd
	enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	zstdCompressed := enc.EncodeAll(originalData, nil)
	results["Zstd"] = base64.RawURLEncoding.EncodeToString(zstdCompressed)
	sizes["Zstd"] = len(zstdCompressed)

	// 4. LZ4
	var lz4Buf bytes.Buffer
	lz4Writer := lz4.NewWriter(&lz4Buf)
	lz4Writer.Write(originalData)
	lz4Writer.Close()
	results["LZ4"] = base64.RawURLEncoding.EncodeToString(lz4Buf.Bytes())
	sizes["LZ4"] = lz4Buf.Len()

	// 5. Brotli
	var brotliBuf bytes.Buffer
	brotliWriter := brotli.NewWriterLevel(&brotliBuf, brotli.BestCompression)
	brotliWriter.Write(originalData)
	brotliWriter.Close()
	results["Brotli"] = base64.RawURLEncoding.EncodeToString(brotliBuf.Bytes())
	sizes["Brotli"] = brotliBuf.Len()

	// Print results
	t.Logf("\nAdvanced compression comparison:")
	t.Logf("Original data length: %d bytes", len(originalData))

	// Sort results by size
	type compressionResult struct {
		name    string
		size    int
		encoded string
	}

	var sortedResults []compressionResult
	for name, size := range sizes {
		sortedResults = append(sortedResults, compressionResult{
			name:    name,
			size:    size,
			encoded: results[name],
		})
	}

	sort.Slice(sortedResults, func(i, j int) bool {
		return sortedResults[i].size < sortedResults[j].size
	})

	for _, result := range sortedResults {
		t.Logf("\n%s:", result.name)
		t.Logf("  Compressed size: %d bytes", result.size)
		t.Logf("  Base64 length: %d", len(result.encoded))
		t.Logf("  Compression ratio: %.2f%%", float64(result.size)/float64(len(originalData))*100)
		t.Logf("  Result: %s", result.encoded)
	}
}

func TestMessagePackComparison(t *testing.T) {
	// Test case
	original := payload.SeedData{
		Scheme: "https",
		Host:   "www.example.com",
		RawURI: "/admin",
		Headers: []payload.Headers{{
			Header: "X-AppEngine-Trusted-IP-Request",
			Value:  "1",
		}},
	}

	bb := &bytesutil.ByteBuffer{}

	bb.B = append(bb.B, 1)
	bb.B = append(bb.B, 0xFF)
	bb.B = append(bb.B, 4)
	bb.Write(make([]byte, 4))

	if original.Scheme != "" {
		bb.B = append(bb.B, 1)
		bb.B = append(bb.B, byte(len(original.Scheme)))
		bb.Write(bytesutil.ToUnsafeBytes(original.Scheme))
	}

	if len(original.Headers) > 0 {
		bb.B = append(bb.B, 2)
		bb.B = append(bb.B, byte(len(original.Headers)))
		for _, h := range original.Headers {
			bb.B = append(bb.B, byte(len(h.Header)))
			bb.Write(bytesutil.ToUnsafeBytes(h.Header))
			bb.B = append(bb.B, byte(len(h.Value)))
			bb.Write(bytesutil.ToUnsafeBytes(h.Value))
		}
	}

	snappyCompressed := snappy.Encode(nil, bb.B)
	snappyResult := base64.RawURLEncoding.EncodeToString(snappyCompressed)

	// MessagePack
	msgpackData, err := msgpack.Marshal(original)
	if err != nil {
		t.Fatalf("MessagePack marshal failed: %v", err)
	}
	msgpackResult := base64.RawURLEncoding.EncodeToString(msgpackData)

	t.Logf("\nCompression comparison:")
	t.Logf("Original struct size: %d bytes", len(bb.B))
	t.Logf("\nSnappy:")
	t.Logf("  Compressed size: %d bytes", len(snappyCompressed))
	t.Logf("  Base64 length: %d chars", len(snappyResult))
	t.Logf("  Result: %s", snappyResult)
	t.Logf("\nMessagePack:")
	t.Logf("  Size: %d bytes", len(msgpackData))
	t.Logf("  Base64 length: %d chars", len(msgpackResult))
	t.Logf("  Result: %s", msgpackResult)

	// Verify MessagePack roundtrip
	var recovered payload.SeedData
	err = msgpack.Unmarshal(msgpackData, &recovered)
	if err != nil {
		t.Fatalf("MessagePack unmarshal failed: %v", err)
	}

	if recovered.Scheme != original.Scheme {
		t.Errorf("URLs don't match")
	}
	if len(recovered.Headers) != len(original.Headers) {
		t.Errorf("Header count mismatch")
	}
	for i, h := range original.Headers {
		if recovered.Headers[i].Header != h.Header || recovered.Headers[i].Value != h.Value {
			t.Errorf("Header %d mismatch", i)
		}
	}
}

func TestPayloadSeedSimple(t *testing.T) {
	urlOnly := payload.BypassPayload{
		Scheme: "https",
		Host:   "example.com",
	}
	seed1 := payload.GeneratePayloadToken(urlOnly)
	recovered1, err := payload.DecodePayloadToken(seed1)
	if err != nil {

		t.Fatalf("Failed to recover URL-only seed: %v", err)
	}
	if recovered1.Scheme != urlOnly.Scheme {
		t.Errorf("URL mismatch: got %s, want %s", recovered1.Scheme, urlOnly.Scheme)
	}
	headerOnly := payload.BypassPayload{
		Headers: []payload.Headers{{
			Header: "X-Test",
			Value:  "test",
		}},
	}

	seed2 := payload.GeneratePayloadToken(headerOnly)
	recovered2, err := payload.DecodePayloadToken(seed2)
	if err != nil {
		t.Fatalf("Failed to recover header-only seed: %v", err)
	}

	if len(recovered2.Headers) != 1 ||
		recovered2.Headers[0].Header != headerOnly.Headers[0].Header ||
		recovered2.Headers[0].Value != headerOnly.Headers[0].Value {
		t.Errorf("Header mismatch: got %+v, want %+v", recovered2.Headers, headerOnly.Headers)
	}
}

type PayloadJobBytes struct {
	OriginalURL  []byte
	Scheme       []byte
	Method       []byte
	Host         []byte
	RawURI       []byte
	Headers      []HeaderBytes
	BypassModule []byte
	FullURL      []byte
}

type HeaderBytes struct {
	Header []byte
	Value  []byte
}

func TestStringVsBytes(t *testing.T) {
	// Original string-based structs
	stringJob := payload.BypassPayload{
		OriginalURL:  "https://www.example.com/admin",
		Method:       "GET",
		Host:         "www.example.com",
		RawURI:       "/admin",
		BypassModule: "header_ip",

		Scheme: "https",
		Headers: []payload.Headers{{
			Header: "X-AppEngine-Trusted-IP-Request",
			Value:  "1",
		}},
	}

	// New byte-based structs
	byteJob := PayloadJobBytes{
		OriginalURL:  []byte("https://www.example.com/admin"),
		Method:       []byte("GET"),
		Host:         []byte("www.example.com"),
		RawURI:       []byte("/admin"),
		BypassModule: []byte("header_ip"),
		Scheme:       []byte("https"),
		Headers: []HeaderBytes{{
			Header: []byte("X-AppEngine-Trusted-IP-Request"),
			Value:  []byte("1"),
		}},
	}

	// Test string-based serialization
	bb1 := &bytesutil.ByteBuffer{}

	bb1.B = append(bb1.B, 1) // version
	bb1.B = append(bb1.B, byte(len(stringJob.Scheme)))
	bb1.Write(bytesutil.ToUnsafeBytes(stringJob.Scheme))
	bb1.B = append(bb1.B, byte(len(stringJob.Headers)))
	for _, h := range stringJob.Headers {
		bb1.B = append(bb1.B, byte(len(h.Header)))
		bb1.Write(bytesutil.ToUnsafeBytes(h.Header))
		bb1.B = append(bb1.B, byte(len(h.Value)))
		bb1.Write(bytesutil.ToUnsafeBytes(h.Value))
	}

	// Test byte-based serialization
	bb2 := &bytesutil.ByteBuffer{}

	bb2.B = append(bb2.B, 1) // version
	bb2.B = append(bb2.B, byte(len(byteJob.FullURL)))
	bb2.Write(byteJob.FullURL)
	bb2.B = append(bb2.B, byte(len(byteJob.Headers)))
	for _, h := range byteJob.Headers {
		bb2.B = append(bb2.B, byte(len(h.Header)))
		bb2.Write(h.Header)
		bb2.B = append(bb2.B, byte(len(h.Value)))
		bb2.Write(h.Value)
	}

	// Compare results
	t.Logf("\nString vs Bytes Comparison:")
	t.Logf("String-based struct:")
	t.Logf("  Memory size: %d bytes", unsafe.Sizeof(stringJob))
	t.Logf("  Serialized size: %d bytes", len(bb1.B))
	t.Logf("  Base64 length: %d", len(base64.RawURLEncoding.EncodeToString(bb1.B)))

	t.Logf("\nByte-based struct:")
	t.Logf("  Memory size: %d bytes", unsafe.Sizeof(byteJob))
	t.Logf("  Serialized size: %d bytes", len(bb2.B))
	t.Logf("  Base64 length: %d", len(base64.RawURLEncoding.EncodeToString(bb2.B)))
}

/*
go test -v -run ^TestSnappyVsZstdCompression$ github.com/slicingmelon/go-bypass-403/tests/integration -v
=== RUN   TestSnappyVsZstdCompression

	payloads_compression_test.go:566:
	    Snappy vs. zstd Compression Comparison:
	payloads_compression_test.go:567: Original serialized data: 129 bytes
	payloads_compression_test.go:568:
	    Snappy compression:
	payloads_compression_test.go:569:   Compressed size: 131 bytes
	payloads_compression_test.go:570:   Base64 token length: 175 chars
	payloads_compression_test.go:571:   Token: gQHwTwH_BKvN7xIBAQECF2Nkbi5wcm9qZWN0MXNlcnZpY2UuY29tAzQvdmlkZW9zLzIwMjQwMS8yNi80NDcxODcyMjEvNzIwUF80MDAwS180NDcxBRWsLm1wNAQBAAUBDlgtT3JpZ2luYWwtVVJMAS8GEGh0dHBfaGVhZGVyc191cmw
	payloads_compression_test.go:573:
	    zstd compression:
	payloads_compression_test.go:574:   Compressed size: 142 bytes
	payloads_compression_test.go:575:   Base64 token length: 190 chars
	payloads_compression_test.go:576:   Token: KLUv_QQACQQAAf8Eq83vEgEBAQIXY2RuLnByb2plY3Qxc2VydmljZS5jb20DNC92aWRlb3MvMjAyNDAxLzI2LzQ0NzE4NzIyMS83MjBQXzQwMDBLXzQ0NzE4NzIyMS5tcDQEAQAFAQ5YLU9yaWdpbmFsLVVSTAEvBhBodHRwX2hlYWRlcnNfdXJspoMaLA
	payloads_compression_test.go:578:
	    Comparison:
	payloads_compression_test.go:580:   zstd is -8.57% smaller than Snappy for this payload
	payloads_compression_test.go:603: ✓ zstd round-trip verified - decompressed data matches original

--- PASS: TestSnappyVsZstdCompression (0.01s)
PASS
ok      github.com/slicingmelon/go-bypass-403/tests/integration 2.382
*/
func TestSnappyVsZstdCompression(t *testing.T) {
	// Create a realistic bypass payload similar to a production example
	testPayload := payload.BypassPayload{
		OriginalURL:  "https://getmysmth.com/afffff/2024sdf01/26/4fsdf47187221/720dsfsdf/1234234/fwsfsdf/sdfsd",
		Scheme:       "https",
		Method:       "GET",
		Host:         "getmysmth.com",
		RawURI:       "/afffff/2024sdf01/26/4fsdf47187221/720dsfsdf/1234234/fwsfsdf/sdfsd",
		BypassModule: "http_headers_url",
		Headers: []payload.Headers{{
			Header: "X-Original-URL",
			Value:  "/",
		}},
	}

	// Serializing the payload (replicating what GeneratePayloadToken does)
	bb := &bytesutil.ByteBuffer{}

	// version
	bb.B = append(bb.B, 1)

	// Add nonce
	bb.B = append(bb.B, 0xFF, 4)
	nonce := []byte{0xAB, 0xCD, 0xEF, 0x12} // Fixed nonce for test consistency
	bb.Write(nonce)

	// Write Scheme
	if testPayload.Scheme != "" {
		bb.B = append(bb.B, 1) // field type for scheme
		if testPayload.Scheme == "https" {
			bb.B = append(bb.B, 1, 1) // length=1, index for https
		} else {
			bb.B = append(bb.B, byte(len(testPayload.Scheme)))
			bb.Write(bytesutil.ToUnsafeBytes(testPayload.Scheme))
		}
	}

	// Write Host
	if testPayload.Host != "" {
		bb.B = append(bb.B, 2) // field type for host
		bb.B = append(bb.B, byte(len(testPayload.Host)))
		bb.Write(bytesutil.ToUnsafeBytes(testPayload.Host))
	}

	// Write RawURI
	if testPayload.RawURI != "" {
		bb.B = append(bb.B, 3) // field type for RawURI
		bb.B = append(bb.B, byte(len(testPayload.RawURI)))
		bb.Write(bytesutil.ToUnsafeBytes(testPayload.RawURI))
	}

	// Write Method
	if testPayload.Method != "" {
		bb.B = append(bb.B, 4) // field type for method
		if testPayload.Method == "GET" {
			bb.B = append(bb.B, 1, 0) // length=1, index for GET
		} else {
			bb.B = append(bb.B, byte(len(testPayload.Method)))
			bb.Write(bytesutil.ToUnsafeBytes(testPayload.Method))
		}
	}

	// Write Headers
	if len(testPayload.Headers) > 0 {
		bb.B = append(bb.B, 5) // field type for headers
		bb.B = append(bb.B, byte(len(testPayload.Headers)))
		for _, h := range testPayload.Headers {
			bb.B = append(bb.B, byte(len(h.Header)))
			bb.Write(bytesutil.ToUnsafeBytes(h.Header))
			bb.B = append(bb.B, byte(len(h.Value)))
			bb.Write(bytesutil.ToUnsafeBytes(h.Value))
		}
	}

	// Write BypassModule
	if testPayload.BypassModule != "" {
		bb.B = append(bb.B, 6) // field type for bypass module
		bb.B = append(bb.B, byte(len(testPayload.BypassModule)))
		bb.Write(bytesutil.ToUnsafeBytes(testPayload.BypassModule))
	}

	// Get current implementation result with Snappy
	snappyCompressed := snappy.Encode(nil, bb.B)
	snappyToken := base64.RawURLEncoding.EncodeToString(snappyCompressed)

	// Try zstd compression
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		t.Fatalf("Failed to create zstd encoder: %v", err)
	}
	zstdCompressed := encoder.EncodeAll(bb.B, nil)
	zstdToken := base64.RawURLEncoding.EncodeToString(zstdCompressed)

	// Output comparison results
	t.Logf("\nSnappy vs. zstd Compression Comparison:")
	t.Logf("Original serialized data: %d bytes", len(bb.B))
	t.Logf("\nSnappy compression:")
	t.Logf("  Compressed size: %d bytes", len(snappyCompressed))
	t.Logf("  Base64 token length: %d chars", len(snappyToken))
	t.Logf("  Token: %s", snappyToken)

	t.Logf("\nzstd compression:")
	t.Logf("  Compressed size: %d bytes", len(zstdCompressed))
	t.Logf("  Base64 token length: %d chars", len(zstdToken))
	t.Logf("  Token: %s", zstdToken)

	t.Logf("\nComparison:")
	percentImprovement := 100 * (1 - float64(len(zstdToken))/float64(len(snappyToken)))
	t.Logf("  zstd is %.2f%% smaller than Snappy for this payload", percentImprovement)

	// Try a mock decoding of the zstd version
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatalf("Failed to create zstd decoder: %v", err)
	}

	// Verify we can decompress zstd correctly
	zstdBytes, err := base64.RawURLEncoding.DecodeString(zstdToken)
	if err != nil {
		t.Fatalf("Failed to decode zstd base64: %v", err)
	}

	decompressed, err := decoder.DecodeAll(zstdBytes, nil)
	if err != nil {
		t.Fatalf("Failed to decompress zstd data: %v", err)
	}

	// Verify decompression was correct by comparing to original
	if !bytes.Equal(decompressed, bb.B) {
		t.Error("zstd decompression produced different data than original")
	} else {
		t.Logf("✓ zstd round-trip verified - decompressed data matches original")
	}
}
