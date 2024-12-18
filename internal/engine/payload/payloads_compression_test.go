package payload

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
	"github.com/slicingmelon/go-bypass-403/internal/engine/rawhttp/bytebufferpool"
	"github.com/vmihailenco/msgpack/v5"
)

func TestCompressionComparison(t *testing.T) {
	// Test case with realistic data
	original := SeedData{
		FullURL: "https://www.example.com/admin",
		Headers: []Header{{
			Header: "X-AppEngine-Trusted-IP-Request",
			Value:  "1",
		}},
	}
	// Current implementation (Snappy)
	bb := bytebufferpool.Get()
	defer bytebufferpool.Put(bb)

	// Write same data format as GeneratePayloadSeed2
	bb.WriteByte(1)           // version
	bb.WriteByte(0xFF)        // nonce field
	bb.WriteByte(8)           // nonce length
	bb.Write(make([]byte, 8)) // dummy nonce

	if original.FullURL != "" {
		bb.WriteByte(1)
		bb.WriteByte(byte(len(original.FullURL)))
		bb.WriteString(original.FullURL)
	}

	if len(original.Headers) > 0 {
		bb.WriteByte(2)
		bb.WriteByte(byte(len(original.Headers)))
		for _, h := range original.Headers {
			bb.WriteByte(byte(len(h.Header)))
			bb.WriteString(h.Header)
			bb.WriteByte(byte(len(h.Value)))
			bb.WriteString(h.Value)
		}
	}
	// Test Snappy (current)
	snappyCompressed := snappy.Encode(nil, bb.Bytes())
	snappyResult := base64.RawURLEncoding.EncodeToString(snappyCompressed)

	// Test Zlib
	var zlibBuf bytes.Buffer
	zw := zlib.NewWriter(&zlibBuf)
	zw.Write(bb.Bytes())
	zw.Close()
	zlibResult := base64.RawURLEncoding.EncodeToString(zlibBuf.Bytes())
	t.Logf("\nCompression comparison for same payload:")
	t.Logf("Original data length: %d bytes", len(bb.Bytes()))
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
	if !bytes.Equal(bb.Bytes(), decompressed) {
		t.Error("Zlib roundtrip failed - data mismatch")
	}
}

func TestCompressionComparisonLargePayload(t *testing.T) {
	// Create a larger test case
	original := SeedData{
		FullURL: "https://www.example.com/admin/dashboard/users/settings?param1=value1&param2=value2",
		Headers: []Header{
			{Header: "X-AppEngine-Trusted-IP-Request", Value: "1"},
			{Header: "X-Forwarded-For", Value: "127.0.0.1"},
			{Header: "X-Original-URL", Value: "/admin/dashboard"},
			{Header: "X-Rewrite-URL", Value: "/admin/dashboard"},
			{Header: "X-Custom-Header", Value: "some-long-value-that-needs-compression"},
		},
	}
	bb := bytebufferpool.Get()
	defer bytebufferpool.Put(bb)

	// Write data
	bb.WriteByte(1)
	bb.WriteByte(0xFF)
	bb.WriteByte(8)
	bb.Write(make([]byte, 8))

	if original.FullURL != "" {
		bb.WriteByte(1)
		bb.WriteByte(byte(len(original.FullURL)))
		bb.WriteString(original.FullURL)
	}

	if len(original.Headers) > 0 {
		bb.WriteByte(2)
		bb.WriteByte(byte(len(original.Headers)))
		for _, h := range original.Headers {
			bb.WriteByte(byte(len(h.Header)))
			bb.WriteString(h.Header)
			bb.WriteByte(byte(len(h.Value)))
			bb.WriteString(h.Value)
		}
	}
	// Test both compressions
	snappyCompressed := snappy.Encode(nil, bb.Bytes())
	snappyResult := base64.RawURLEncoding.EncodeToString(snappyCompressed)

	var zlibBuf bytes.Buffer
	zw := zlib.NewWriter(&zlibBuf)
	zw.Write(bb.Bytes())
	zw.Close()
	zlibResult := base64.RawURLEncoding.EncodeToString(zlibBuf.Bytes())
	t.Logf("\nLarge payload compression comparison:")
	t.Logf("Original data length: %d bytes", len(bb.Bytes()))
	t.Logf("Snappy compressed length: %d bytes, Base64 length: %d", len(snappyCompressed), len(snappyResult))
	t.Logf("Zlib compressed length: %d bytes, Base64 length: %d", zlibBuf.Len(), len(zlibResult))
	t.Logf("\nSnappy result: %s", snappyResult)
	t.Logf("Zlib result: %s", zlibResult)
}

func TestAdvancedCompressionComparison(t *testing.T) {
	original := SeedData{
		FullURL: "https://www.example.com/admin/dashboard/users/settings?param1=value1&param2=value2&param3=value3",
		Headers: []Header{
			{Header: "X-AppEngine-Trusted-IP-Request", Value: "1"},
			{Header: "X-Forwarded-For", Value: "127.0.0.1, 10.0.0.1, 192.168.1.1"},
			{Header: "X-Original-URL", Value: "/admin/dashboard/users/settings"},
			{Header: "X-Rewrite-URL", Value: "/admin/dashboard/users/settings"},
			{Header: "X-Custom-Header", Value: "some-long-value-that-needs-compression-and-repeats-some-long-value"},
			{Header: "X-Custom-Header2", Value: "some-long-value-that-needs-compression-and-repeats-some-long-value"},
		},
	}
	bb := bytebufferpool.Get()
	defer bytebufferpool.Put(bb)

	// Write data
	bb.WriteByte(1)
	bb.WriteByte(0xFF)
	bb.WriteByte(4) // reduced nonce size
	bb.Write(make([]byte, 4))

	if original.FullURL != "" {
		bb.WriteByte(1)
		bb.WriteByte(byte(len(original.FullURL)))
		bb.WriteString(original.FullURL)
	}

	if len(original.Headers) > 0 {
		bb.WriteByte(2)
		bb.WriteByte(byte(len(original.Headers)))
		for _, h := range original.Headers {
			bb.WriteByte(byte(len(h.Header)))
			bb.WriteString(h.Header)
			bb.WriteByte(byte(len(h.Value)))
			bb.WriteString(h.Value)
		}
	}
	originalData := bb.Bytes()
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
	original := SeedData{
		FullURL: "https://www.example.com/admin",
		Headers: []Header{{
			Header: "X-AppEngine-Trusted-IP-Request",
			Value:  "1",
		}},
	}
	// Current method (Snappy)
	bb := bytebufferpool.Get()
	defer bytebufferpool.Put(bb)

	bb.WriteByte(1)
	bb.WriteByte(0xFF)
	bb.WriteByte(4)
	bb.Write(make([]byte, 4))

	if original.FullURL != "" {
		bb.WriteByte(1)
		bb.WriteByte(byte(len(original.FullURL)))
		bb.WriteString(original.FullURL)
	}

	if len(original.Headers) > 0 {
		bb.WriteByte(2)
		bb.WriteByte(byte(len(original.Headers)))
		for _, h := range original.Headers {
			bb.WriteByte(byte(len(h.Header)))
			bb.WriteString(h.Header)
			bb.WriteByte(byte(len(h.Value)))
			bb.WriteString(h.Value)
		}
	}
	snappyCompressed := snappy.Encode(nil, bb.Bytes())
	snappyResult := base64.RawURLEncoding.EncodeToString(snappyCompressed)
	// MessagePack
	msgpackData, err := msgpack.Marshal(original)
	if err != nil {
		t.Fatalf("MessagePack marshal failed: %v", err)
	}
	msgpackResult := base64.RawURLEncoding.EncodeToString(msgpackData)
	t.Logf("\nCompression comparison:")
	t.Logf("Original struct size: %d bytes", len(bb.Bytes()))
	t.Logf("\nSnappy:")
	t.Logf("  Compressed size: %d bytes", len(snappyCompressed))
	t.Logf("  Base64 length: %d chars", len(snappyResult))
	t.Logf("  Result: %s", snappyResult)
	t.Logf("\nMessagePack:")
	t.Logf("  Size: %d bytes", len(msgpackData))
	t.Logf("  Base64 length: %d chars", len(msgpackResult))
	t.Logf("  Result: %s", msgpackResult)
	// Verify MessagePack roundtrip
	var recovered SeedData
	err = msgpack.Unmarshal(msgpackData, &recovered)
	if err != nil {
		t.Fatalf("MessagePack unmarshal failed: %v", err)
	}
	if recovered.FullURL != original.FullURL {
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
	urlOnly := SeedData{
		FullURL: "https://example.com",
	}
	seed1 := GenerateDebugToken(urlOnly)
	recovered1, err := DecodeDebugToken(seed1)
	if err != nil {
		t.Fatalf("Failed to recover URL-only seed: %v", err)
	}
	if recovered1.FullURL != urlOnly.FullURL {
		t.Errorf("URL mismatch: got %s, want %s", recovered1.FullURL, urlOnly.FullURL)
	}
	headerOnly := SeedData{
		Headers: []Header{{
			Header: "X-Test",
			Value:  "test",
		}},
	}
	seed2 := GenerateDebugToken(headerOnly)
	recovered2, err := DecodeDebugToken(seed2)
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
	stringJob := PayloadJob{
		OriginalURL:  "https://www.example.com/admin",
		Method:       "GET",
		Host:         "www.example.com",
		RawURI:       "/admin",
		BypassModule: "header_ip",
		FullURL:      "https://www.example.com/admin",
		Headers: []Header{{
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
		FullURL:      []byte("https://www.example.com/admin"),
		Headers: []HeaderBytes{{
			Header: []byte("X-AppEngine-Trusted-IP-Request"),
			Value:  []byte("1"),
		}},
	}
	// Test string-based serialization
	bb1 := bytebufferpool.Get()
	defer bytebufferpool.Put(bb1)

	bb1.WriteByte(1) // version
	bb1.WriteByte(byte(len(stringJob.FullURL)))
	bb1.WriteString(stringJob.FullURL)
	bb1.WriteByte(byte(len(stringJob.Headers)))
	for _, h := range stringJob.Headers {
		bb1.WriteByte(byte(len(h.Header)))
		bb1.WriteString(h.Header)
		bb1.WriteByte(byte(len(h.Value)))
		bb1.WriteString(h.Value)
	}

	// Test byte-based serialization
	bb2 := bytebufferpool.Get()
	defer bytebufferpool.Put(bb2)

	bb2.WriteByte(1) // version
	bb2.WriteByte(byte(len(byteJob.FullURL)))
	bb2.Write(byteJob.FullURL)
	bb2.WriteByte(byte(len(byteJob.Headers)))
	for _, h := range byteJob.Headers {
		bb2.WriteByte(byte(len(h.Header)))
		bb2.Write(h.Header)
		bb2.WriteByte(byte(len(h.Value)))
		bb2.Write(h.Value)
	}
	// Compare results
	t.Logf("\nString vs Bytes Comparison:")
	t.Logf("String-based struct:")
	t.Logf("  Memory size: %d bytes", unsafe.Sizeof(stringJob))
	t.Logf("  Serialized size: %d bytes", bb1.Len())
	t.Logf("  Base64 length: %d", len(base64.RawURLEncoding.EncodeToString(bb1.Bytes())))

	t.Logf("\nByte-based struct:")
	t.Logf("  Memory size: %d bytes", unsafe.Sizeof(byteJob))
	t.Logf("  Serialized size: %d bytes", bb2.Len())
	t.Logf("  Base64 length: %d", len(base64.RawURLEncoding.EncodeToString(bb2.Bytes())))
}
