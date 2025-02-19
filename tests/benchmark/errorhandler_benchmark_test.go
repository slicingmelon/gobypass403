package tests

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
)

func BenchmarkErrorHandler(b *testing.B) {
	handler := GB403ErrorHandler.GetErrorHandler()
	testErr := fmt.Errorf("test error")
	bypassPayload := payload.BypassPayload{
		BypassModule: "test-module",
		PayloadToken: "test-token",
	}

	// Basic error context creation
	b.Run("create_error_context", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			errCtx := GB403ErrorHandler.ErrorContext{
				ErrorSource:  "execFunc",
				Host:         "test.com",
				BypassModule: bypassPayload.BypassModule,
				DebugToken:   bypassPayload.PayloadToken,
			}
			_ = errCtx
		}
	})

	// Just the error key generation
	b.Run("generate_error_key", func(b *testing.B) {
		b.ReportAllocs()
		host := "test.com"
		errMsg := "test error"
		for i := 0; i < b.N; i++ {
			key := []byte(fmt.Sprintf("h:%s:e:%s", host, errMsg))
			_ = key
		}
	})

	// Cache operations
	b.Run("cache_operations", func(b *testing.B) {
		b.ReportAllocs()
		errCtx := GB403ErrorHandler.ErrorContext{
			ErrorSource:  "execFunc2",
			Host:         "test.com",
			BypassModule: "test-module",
			DebugToken:   "test-token",
		}
		for i := 0; i < b.N; i++ {
			handler.HandleError(testErr, errCtx)
		}
	})

	// JSON marshaling/unmarshaling
	b.Run("json_operations", func(b *testing.B) {
		b.ReportAllocs()
		stats := &GB403ErrorHandler.ErrorStats{}
		stats.Count.Store(1)
		now := time.Now()
		stats.FirstSeen = now
		stats.LastSeen.Store(&now)
		for i := 0; i < b.N; i++ {
			data, _ := json.Marshal(stats)
			var newStats GB403ErrorHandler.ErrorStats
			_ = json.Unmarshal(data, &newStats)
		}
	})

	// Full error handling path with index updates
	b.Run("full_error_handling", func(b *testing.B) {
		b.ReportAllocs()
		handler.Reset() // Clear previous state
		for i := 0; i < b.N; i++ {
			errCtx := GB403ErrorHandler.ErrorContext{
				ErrorSource:  "execFunc",
				Host:         "test.com",
				BypassModule: "test-module",
				DebugToken:   "test-token",
			}
			handler.HandleError(testErr, errCtx)
		}
	})

	b.Run("print_error_stats", func(b *testing.B) {
		b.ReportAllocs()
		// Setup some test data first
		errCtx := GB403ErrorHandler.ErrorContext{
			ErrorSource:  "execFunc",
			Host:         "test.com",
			BypassModule: "test-module",
			DebugToken:   "test-token",
		}
		// Add some errors to have something to print
		for i := 0; i < 10; i++ {
			handler.HandleError(testErr, errCtx)
		}

		// Benchmark the print operation
		b.ResetTimer() // Reset timer after setup
		for i := 0; i < b.N; i++ {
			handler.PrintErrorStats()
		}
	})
}
