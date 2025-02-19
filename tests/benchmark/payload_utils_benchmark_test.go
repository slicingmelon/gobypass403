package tests

import (
	"fmt"
	"testing"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
)

/*
make wins over pool and sprintf

BenchmarkBypassPayloadToBaseURL
BenchmarkBypassPayloadToBaseURL/with_pool
BenchmarkBypassPayloadToBaseURL/with_pool-20
20745991	        60.15 ns/op	      32 B/op	       2 allocs/op
BenchmarkBypassPayloadToBaseURL/with_make
BenchmarkBypassPayloadToBaseURL/with_make-20
46353880	        28.99 ns/op	      24 B/op	       1 allocs/op
BenchmarkBypassPayloadToBaseURL/with_sprintf
BenchmarkBypassPayloadToBaseURL/with_sprintf-20
10295320	       120.5 ns/op	      56 B/op	       3 allocs/op
PASS
ok  	github.com/slicingmelon/go-bypass-403/tests/benchmark	5.679s
*/
func BenchmarkBypassPayloadToBaseURL(b *testing.B) {
	testPayload := payload.BypassPayload{
		Scheme: "https",
		Host:   "example.com",
		RawURI: "/path/to/resource",
		Headers: []payload.Headers{
			{
				Header: "Content-Type",
				Value:  "application/json",
			},
		},
	}

	b.Run("with_pool", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = payload.BypassPayloadToBaseURL(testPayload)
		}
	})

	b.Run("with_make", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = payload.BypassPayloadToBaseURL(testPayload)
		}
	})

	b.Run("with_sprintf", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = fmt.Sprintf("%s://%s", testPayload.Scheme, testPayload.Host)
		}
	})
}

/*
BenchmarkBypassPayloadToFullURL
BenchmarkBypassPayloadToFullURL/with_make
BenchmarkBypassPayloadToFullURL/with_make-20
21824808	        56.18 ns/op	      96 B/op	       2 allocs/op
BenchmarkBypassPayloadToFullURL/with_sprintf
BenchmarkBypassPayloadToFullURL/with_sprintf-20

7892940	       147.0 ns/op	      96 B/op	       4 allocs/op

PASS
ok  	github.com/slicingmelon/go-bypass-403/tests/benchmark	4.621
*/
func BenchmarkBypassPayloadToFullURL(b *testing.B) {
	testPayload := payload.BypassPayload{
		Scheme: "https",
		Host:   "example.com",
		RawURI: "/path/to/resource",
	}

	b.Run("with_make", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = payload.BypassPayloadToFullURL(testPayload)
		}
	})

	b.Run("with_sprintf", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = fmt.Sprintf("%s://%s%s", testPayload.Scheme, testPayload.Host, testPayload.RawURI)
		}
	})
}
