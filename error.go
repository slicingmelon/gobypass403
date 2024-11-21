// error.go
package main

import (
	"strings"
	"time"

	"github.com/projectdiscovery/gcache"
	"github.com/projectdiscovery/utils/errkit"
)

// ----------------------------------//
// Ctustom Error Handling 			//
// ---------------------------------//
var (
	globalErrorHandler *ErrorHandler
)

var (
	ErrKindGo403BypassFatal = errkit.NewPrimitiveErrKind(
		"error-go-403-bypass-fatal",
		"error go 403 bypass fatal",
		nil,
	)

	ErrKindGo403Temporary = errkit.NewPrimitiveErrKind(
		"error-go-403-bypass-temporary",
		"error go 403 bypass temporary",
		isGo403TemporaryErr,
	)
)

// Helper function to identify temporary errors specific to go-403-bypass
func isGo403TemporaryErr(err *errkit.ErrorX) bool {
	if err.Cause() == nil {
		return false
	}
	v := err.Cause().Error()
	return strings.Contains(v, "forcibly closed by the remote host")
}

// Define our custom errors
var (
	ErrForciblyClosed = errkit.New("connection forcibly closed by remote host").
		SetKind(ErrKindGo403Temporary).
		Build()
)

// ErrorHandler manages error states and client lifecycle
type ErrorHandler struct {
	hostErrors       gcache.Cache[string, int]
	lastErrorTime    gcache.Cache[string, time.Time]
	maxErrors        int
	maxErrorDuration time.Duration
}

// NewErrorHandler creates a new error handler
func NewErrorHandler() *ErrorHandler {
	return &ErrorHandler{
		hostErrors: gcache.New[string, int](1000).
			ARC(). // Adaptive Replacement Cache
			Build(),
		lastErrorTime: gcache.New[string, time.Time](1000).
			ARC().
			Build(),
		maxErrors:        15,
		maxErrorDuration: 1 * time.Minute,
	}
}

// HandleError processes errors and determines if they're permanent
func (h *ErrorHandler) HandleError(err error, host string) error {
	if err == nil {
		return nil
	}

	errx := errkit.FromError(err)

	// Only handle our custom temporary errors
	if errx.Kind() == ErrKindGo403Temporary {
		now := time.Now()
		errorCount, _ := h.hostErrors.GetIFPresent(host)
		errorCount++
		_ = h.hostErrors.Set(host, errorCount)

		lastTime, _ := h.lastErrorTime.GetIFPresent(host)

		if !lastTime.IsZero() && now.Sub(lastTime) <= h.maxErrorDuration {
			if errorCount >= h.maxErrors {
				// Convert to our custom fatal error
				errx.ResetKind().SetKind(ErrKindGo403BypassFatal)
				return errkit.WithMessagef(errx.Build(),
					"[go-403-bypass-error-handler]: max errors (%d) reached within %v for host %s",
					h.maxErrors, h.maxErrorDuration, host)
			}
		} else {
			errorCount = 1
			_ = h.hostErrors.Set(host, errorCount)
		}
		_ = h.lastErrorTime.Set(host, now)
	}

	return errx.Build()
}

// Purge cleans up the caches
func (h *ErrorHandler) Purge() {
	h.hostErrors.Purge()
	h.lastErrorTime.Purge()
}
