package tests

import (
	"fmt"
	"testing"

	"github.com/slicingmelon/go-bypass-403/internal/engine/payload"
	GB403ErrorHandler "github.com/slicingmelon/go-bypass-403/internal/utils/error"
)

func BenchmarkErrorHandlerNew(b *testing.B) {
	handler := GB403ErrorHandler.GetErrorHandler()
	testErr := fmt.Errorf("test error")
	longTestErr := fmt.Errorf("this is a very long error message that exceeds the maximum length limit and should be truncated to make sure we don't store excessively long error messages in our error tracking system which could lead to memory issues if we have many errors with very long messages that repeat frequently in high-traffic scenarios with lots of bypass modules and various error sources")
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

	// Error message stripping
	b.Run("strip_error_message", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			stripped := handler.StripErrorMessage(longTestErr)
			_ = stripped
		}
	})

	// Whitelist checking
	b.Run("whitelist_checking", func(b *testing.B) {
		b.ReportAllocs()
		handler.AddWhitelistedErrors("whitelisted error")
		whitelistedErr := fmt.Errorf("whitelisted error")
		for i := 0; i < b.N; i++ {
			isWhitelisted := handler.IsWhitelistedErrNew(whitelistedErr)
			_ = isWhitelisted
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

	// HandleErrorAndContinue
	b.Run("handle_error_and_continue", func(b *testing.B) {
		b.ReportAllocs()
		errCtx := GB403ErrorHandler.ErrorContext{
			ErrorSource:  "execFunc3",
			Host:         "different-test.com",
			BypassModule: "test-module-2",
			DebugToken:   "different-token",
		}
		for i := 0; i < b.N; i++ {
			handler.HandleErrorAndContinue(testErr, errCtx)
		}
	})

	// Multi-host scenario
	b.Run("multi_host_errors", func(b *testing.B) {
		b.ReportAllocs()
		hosts := []string{"host1.com", "host2.com", "host3.com", "host4.com"}
		handler.Reset() // Clear previous state

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			host := hosts[i%len(hosts)]
			errCtx := GB403ErrorHandler.ErrorContext{
				ErrorSource:  "execFunc-" + host,
				Host:         host,
				BypassModule: "test-module",
				DebugToken:   "test-token-" + host,
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
