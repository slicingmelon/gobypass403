package bytebufferpool

import (
	"bytes"
	"fmt"
	"math/rand"
	"sync"
	"testing"
)

func BenchmarkByteBufferWrite(b *testing.B) {
	s := []byte("foobarbaz")
	b.RunParallel(func(pb *testing.PB) {
		var buf ByteBuffer
		for pb.Next() {
			for i := 0; i < 100; i++ {
				buf.Write(s)
			}
			buf.Reset()
		}
	})
}

func BenchmarkBytesBufferWrite(b *testing.B) {
	s := []byte("foobarbaz")
	b.RunParallel(func(pb *testing.PB) {
		var buf bytes.Buffer
		for pb.Next() {
			for i := 0; i < 100; i++ {
				buf.Write(s)
			}
			buf.Reset()
		}
	})
}

// FAILS
func BenchmarkByteBufferConcurrentWrites(b *testing.B) {
	bb := Get()
	defer Put(bb)

	data := []byte("test data for concurrent writes")

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			bb.Write(data)
		}
	})
}

func BenchmarkByteBufferConcurrentWrites2(b *testing.B) {
	bb := Get()
	defer Put(bb)

	data := []byte("test data for concurrent writes")
	var mu sync.Mutex // Add mutex for synchronization

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mu.Lock()
			bb.Write(data)
			mu.Unlock()
		}
	})
}

func BenchmarkByteBufferLargeWrites(b *testing.B) {
	sizes := []int{64, 1024, 16384, 65536}

	for _, size := range sizes {
		data := make([]byte, size)
		rand.Read(data)

		b.Run(fmt.Sprintf("size-%d", size), func(b *testing.B) {
			bb := Get()
			defer Put(bb)

			for i := 0; i < b.N; i++ {
				bb.Write(data)
				bb.Reset()
			}
		})
	}
}

func BenchmarkByteBufferSingleWrites(b *testing.B) {
	bb := Get()
	defer Put(bb)

	data := []byte("test data for single writes")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bb.Write(data)
		if i%100 == 0 { // Reset periodically to prevent excessive growth
			bb.Reset()
		}
	}
}

// Add benchmark comparing multiple independent buffers
func BenchmarkByteBufferMultipleWrites(b *testing.B) {
	data := []byte("test data for multiple writes")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		bb := Get() // Each goroutine gets its own buffer
		defer Put(bb)

		for pb.Next() {
			bb.Write(data)
			if bb.Len() > 1024 { // Reset if buffer gets too large
				bb.Reset()
			}
		}
	})
}

// Add benchmark for different write sizes
func BenchmarkByteBufferWriteSizes(b *testing.B) {
	sizes := []int{64, 128, 512, 1024, 4096}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size-%d", size), func(b *testing.B) {
			data := make([]byte, size)
			rand.Read(data)

			bb := Get()
			defer Put(bb)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				bb.Write(data)
				if i%100 == 0 {
					bb.Reset()
				}
			}
		})
	}
}

func BenchmarkByteBufferPoolStress(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			bb := Get()
			bb.Write([]byte("test"))
			Put(bb)
		}
	})
}
