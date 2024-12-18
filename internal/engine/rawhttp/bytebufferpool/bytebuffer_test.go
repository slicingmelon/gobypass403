package bytebufferpool

import (
	"bytes"
	cryptorand "crypto/rand"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestByteBufferReadFrom(t *testing.T) {
	prefix := "foobar"
	expectedS := "asadfsdafsadfasdfisdsdfa"
	prefixLen := int64(len(prefix))
	expectedN := int64(len(expectedS))

	var bb ByteBuffer
	bb.WriteString(prefix)

	rf := (io.ReaderFrom)(&bb)
	for i := 0; i < 20; i++ {
		r := bytes.NewBufferString(expectedS)
		n, err := rf.ReadFrom(r)
		if n != expectedN {
			t.Fatalf("unexpected n=%d. Expecting %d. iteration %d", n, expectedN, i)
		}
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		bbLen := int64(bb.Len())
		expectedLen := prefixLen + int64(i+1)*expectedN
		if bbLen != expectedLen {
			t.Fatalf("unexpected byteBuffer length: %d. Expecting %d", bbLen, expectedLen)
		}
		for j := 0; j < i; j++ {
			start := prefixLen + int64(j)*expectedN
			b := bb.B[start : start+expectedN]
			if string(b) != expectedS {
				t.Fatalf("unexpected byteBuffer contents: %q. Expecting %q", b, expectedS)
			}
		}
	}
}

func TestByteBufferWriteTo(t *testing.T) {
	expectedS := "foobarbaz"
	var bb ByteBuffer
	bb.WriteString(expectedS[:3])
	bb.WriteString(expectedS[3:])

	wt := (io.WriterTo)(&bb)
	var w bytes.Buffer
	for i := 0; i < 10; i++ {
		n, err := wt.WriteTo(&w)
		if n != int64(len(expectedS)) {
			t.Fatalf("unexpected n returned from WriteTo: %d. Expecting %d", n, len(expectedS))
		}
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		s := w.String()
		if s != expectedS {
			t.Fatalf("unexpected string written %q. Expecting %q", s, expectedS)
		}
		w.Reset()
	}
}

func TestByteBufferGetPutSerial(t *testing.T) {
	testByteBufferGetPut(t)
}

func TestByteBufferGetPutConcurrent(t *testing.T) {
	concurrency := 10
	ch := make(chan struct{}, concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			testByteBufferGetPut(t)
			ch <- struct{}{}
		}()
	}

	for i := 0; i < concurrency; i++ {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatalf("timeout!")
		}
	}
}

func testByteBufferGetPut(t *testing.T) {
	for i := 0; i < 10; i++ {
		expectedS := fmt.Sprintf("num %d", i)
		b := Get()
		b.B = append(b.B, "num "...)
		b.B = append(b.B, fmt.Sprintf("%d", i)...)
		if string(b.B) != expectedS {
			t.Fatalf("unexpected result: %q. Expecting %q", b.B, expectedS)
		}
		Put(b)
	}
}

func testByteBufferGetString(t *testing.T) {
	for i := 0; i < 10; i++ {
		expectedS := fmt.Sprintf("num %d", i)
		b := Get()
		b.SetString(expectedS)
		if b.String() != expectedS {
			t.Fatalf("unexpected result: %q. Expecting %q", b.B, expectedS)
		}
		Put(b)
	}
}

func TestByteBufferGetStringSerial(t *testing.T) {
	testByteBufferGetString(t)
}

func TestByteBufferGetStringConcurrent(t *testing.T) {
	concurrency := 10
	ch := make(chan struct{}, concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			testByteBufferGetString(t)
			ch <- struct{}{}
		}()
	}

	for i := 0; i < concurrency; i++ {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatalf("timeout!")
		}
	}
}

func TestByteBufferConcurrentAccess(t *testing.T) {
	t.Parallel()

	const (
		goroutines = 8
		iterations = 1000
	)

	bb := Get()
	defer Put(bb)

	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Test concurrent writes
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				data := []byte(fmt.Sprintf("goroutine-%d-iter-%d", id, j))
				bb.Write(data)
			}
		}(i)
	}

	wg.Wait()
}

func TestByteBufferLargeWrites(t *testing.T) {
	bb := Get()
	defer Put(bb)

	// Test with increasing sizes
	sizes := []int{64, 128, 512, 1024, 4096, 16384, 65536}

	for _, size := range sizes {
		data := make([]byte, size)
		cryptorand.Read(data)

		n, err := bb.Write(data)
		if err != nil {
			t.Errorf("failed to write %d bytes: %v", size, err)
		}
		if n != size {
			t.Errorf("wrote %d bytes, expected %d", n, size)
		}

		bb.Reset()
	}
}

func TestByteBufferReset(t *testing.T) {
	bb := Get()
	defer Put(bb)

	data := []byte("test data")
	bb.Write(data)

	// Test that Reset actually clears the buffer
	bb.Reset()
	if len(bb.B) != 0 {
		t.Errorf("buffer not empty after Reset(): len=%d", len(bb.B))
	}

	// Test that capacity is preserved
	originalCap := cap(bb.B)
	bb.Reset()
	if cap(bb.B) != originalCap {
		t.Errorf("capacity changed after Reset(): was %d, now %d", originalCap, cap(bb.B))
	}
}

func TestByteBufferGrowth(t *testing.T) {
	bb := Get()
	defer Put(bb)

	// First, ensure we have some initial capacity
	initialData := []byte("initial")
	bb.Write(initialData)
	bb.Reset() // Reset but keep capacity

	initialCap := cap(bb.B)
	if initialCap == 0 {
		t.Fatal("expected non-zero initial capacity")
	}

	// Test growth with data larger than initial capacity
	data := make([]byte, initialCap*2)
	cryptorand.Read(data)

	bb.Write(data)

	newCap := cap(bb.B)
	if newCap <= initialCap {
		t.Errorf("buffer didn't grow: newCap=%d, initialCap=%d", newCap, initialCap)
	}

	// Verify content
	if !bytes.Equal(bb.B, data) {
		t.Error("buffer contents don't match written data")
	}

	// Test multiple growth steps
	for i := 0; i < 3; i++ {
		prevCap := cap(bb.B)
		moreData := make([]byte, prevCap*2)
		cryptorand.Read(moreData)

		bb.Write(moreData)

		if cap(bb.B) <= prevCap {
			t.Errorf("iteration %d: buffer didn't grow: current=%d, previous=%d",
				i, cap(bb.B), prevCap)
		}
	}
}

func TestByteBufferStringSafety(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"empty", []byte{}, ""},
		{"ascii", []byte("hello world"), "hello world"},
		{"utf8", []byte("hello 世界"), "hello 世界"},
		{"null bytes", []byte{0, 'a', 0, 'b'}, string([]byte{0, 'a', 0, 'b'})},
		{"high bytes", []byte{0xFF, 0xFE, 0xFD}, string([]byte{0xFF, 0xFE, 0xFD})},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			bb := Get()
			defer Put(bb)

			bb.Write(tc.input)

			// Get string representation
			s1 := bb.String()

			// Verify the string matches expected
			if s1 != tc.expected {
				t.Errorf("String() = %q; want %q", s1, tc.expected)
			}

			// Modify buffer after String() call
			if len(bb.B) > 0 {
				bb.B[0] = 'X'

				// Get string again
				s2 := bb.String()

				// Verify first string wasn't modified
				if s1 == s2 {
					t.Error("String contents changed when underlying buffer was modified")
				}
			}
		})
	}
}

func TestByteBufferStringConcurrent(t *testing.T) {
	t.Parallel()

	bb := Get()
	defer Put(bb)

	const goroutines = 4
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < iterations; j++ {
				// Write some data
				data := fmt.Sprintf("goroutine-%d-%d", id, j)
				bb.WriteString(data)

				// Get string representation
				_ = bb.String()

				// Modify buffer
				bb.Reset()
			}
		}(i)
	}

	wg.Wait()
}

// Test for memory safety
func TestByteBufferStringMemoryLeak(t *testing.T) {
	var m runtime.MemStats

	// Run GC and get initial memory stats
	runtime.GC()
	runtime.ReadMemStats(&m)
	initialAlloc := m.Alloc

	// Create and destroy many strings
	for i := 0; i < 1000; i++ {
		bb := Get()
		bb.WriteString(strings.Repeat("x", 1000))
		_ = bb.String()
		Put(bb)
	}

	// Run GC and check memory stats again
	runtime.GC()
	runtime.ReadMemStats(&m)
	finalAlloc := m.Alloc

	// Check for significant memory growth
	if finalAlloc > initialAlloc*2 {
		t.Errorf("Possible memory leak: initial=%d final=%d", initialAlloc, finalAlloc)
	}
}

func TestByteBufferBasicOperations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		fn   func(*testing.T)
	}{
		{"empty-writes", func(t *testing.T) {
			bb := Get()
			defer Put(bb)

			// Test edge cases
			bb.Write(nil)      // empty write
			bb.Write([]byte{}) // zero-length write
			bb.WriteString("") // empty string

			if len(bb.B) != 0 {
				t.Error("buffer should be empty")
			}
		}},
		{"reset-behavior", func(t *testing.T) {
			bb := Get()
			defer Put(bb)

			bb.WriteString("test")
			bb.Reset()

			if len(bb.B) != 0 {
				t.Error("Reset didn't clear buffer")
			}

			// Capacity should be preserved
			if cap(bb.B) == 0 {
				t.Error("Reset shouldn't affect capacity")
			}
		}},
		{"set-operations", func(t *testing.T) {
			bb := Get()
			defer Put(bb)

			testData := []byte("test")
			bb.Set(testData)

			if !bytes.Equal(bb.B, testData) {
				t.Error("Set didn't store data correctly")
			}

			bb.SetString("test2")
			if string(bb.B) != "test2" {
				t.Error("SetString didn't store data correctly")
			}
		}},
		{"buffer-growth", func(t *testing.T) {
			bb := Get()
			defer Put(bb)

			// Write increasing sizes
			sizes := []int{64, 128, 256, 512, 1024}
			for _, size := range sizes {
				data := make([]byte, size)
				bb.Write(data)
			}

			// Just verify we can write and grow
			if cap(bb.B) < 1024 {
				t.Error("buffer didn't grow as expected")
			}
		}},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.fn(t)
		})
	}
}

// TestByteBufferPoolExhaustion tests pool resource exhaustion
func TestByteBufferPoolExhaustion(t *testing.T) {
	const numGoroutines = 1000
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	start := make(chan struct{})
	var failures int32

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			<-start // Synchronize goroutines

			for j := 0; j < opsPerGoroutine; j++ {
				bb := Get()
				if bb == nil {
					atomic.AddInt32(&failures, 1)
					continue
				}
				// Simulate work
				bb.Write([]byte("test"))
				Put(bb)
			}
		}()
	}

	close(start) // Start all goroutines
	wg.Wait()

	if failures > 0 {
		t.Errorf("Pool exhaustion detected: %d failures", failures)
	}
}

// TestByteBufferSanitization verifies input sanitization
func TestByteBufferSanitization(t *testing.T) {
	bb := Get()
	defer Put(bb)

	maliciousInputs := []struct {
		name  string
		input []byte
	}{
		{"large-allocation", make([]byte, 1<<20)}, // 1MB
		{"null-bytes", []byte("test\x00data")},
		{"special-chars", []byte("test\r\n\t\b")},
		{"unicode", []byte("test世界")},
		{"control-chars", []byte{0x00, 0x1B, 0x7F}}, // NULL, ESC, DEL
	}

	for _, tc := range maliciousInputs {
		t.Run(tc.name, func(t *testing.T) {
			bb.Reset()
			bb.Write(tc.input)

			// Verify data integrity
			if !bytes.Equal(bb.B, tc.input) {
				t.Error("data corruption detected")
			}

			// Verify string conversion safety
			s := bb.String()
			if len(s) != len(tc.input) {
				t.Error("string conversion modified data length")
			}
		})
	}
}
