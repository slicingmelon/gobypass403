// client.go
package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/Mzack9999/gcache"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/utils/errkit"
)

type GO403BYPASS struct {
	rawClient    *rawhttp.Client
	errorHandler *ErrorHandler
	dialer       *fastdialer.Dialer
}

// initRawHTTPClient -- initializes the rawhttp client
func initRawHTTPClient(*GO403BYPASS, error) {
	Go403HTTPClient := &GO403BYPASS{}

	// Set fastdialer options from scratch
	fastdialerOpts := fastdialer.Options{
		BaseResolvers: []string{
			"1.1.1.1:53",
			"1.0.0.1:53",
			"9.9.9.10:53",
			"8.8.4.4:53",
		},
		MaxRetries:    5,
		HostsFile:     true,
		ResolversFile: true,
		CacheType:     fastdialer.Disk,
		DiskDbType:    fastdialer.LevelDB,

		// Timeouts
		DialerTimeout:   10 * time.Second,
		DialerKeepAlive: 10 * time.Second,

		// Cache settings
		CacheMemoryMaxItems: 200,
		WithDialerHistory:   true,
		WithCleanup:         true,

		// TLS settings
		WithZTLS:            true,
		DisableZtlsFallback: false,

		// Fallback settings
		EnableFallback: true,

		// Error handling
		MaxTemporaryErrors:              15,
		MaxTemporaryToPermanentDuration: 2 * time.Minute, // Our custom value (default was 1 minute)
	}

	// Use fastdialer
	var err error
	Go403HTTPClient.dialer, err = fastdialer.NewDialer(fastdialerOpts)
	if err != nil {
		return nil, fmt.Errorf("could not create dialer: %v", err)
	}

	options := &rawhttp.Options{
		Timeout:                time.Duration(config.Timeout) * time.Second,
		FollowRedirects:        config.FollowRedirects,
		MaxRedirects:           map[bool]int{false: 0, true: 10}[config.FollowRedirects],
		AutomaticHostHeader:    false,
		AutomaticContentLength: true,
		ForceReadAllBody:       true,
		FastDialer:             Go403HTTPClient.dialer,
	}

	if config.Proxy != "" {
		if !strings.HasPrefix(config.Proxy, "http://") && !strings.HasPrefix(config.Proxy, "https://") {
			config.Proxy = "http://" + config.Proxy
		}
		options.Proxy = config.Proxy
		options.ProxyDialTimeout = 10 * time.Second
	}

	Go403HTTPClient.errorHandler = NewErrorHandler()
	Go403HTTPClient.rawClient = rawhttp.NewClient(options)

	return Go403HTTPClient, nil
}

// Close cleans up resources
func (b *GO403BYPASS) Close() {
	if b.rawClient != nil {
		b.rawClient.Close()
	}
	if b.dialer != nil {
		b.dialer.Close()
	}
	if b.errorHandler != nil {
		b.errorHandler.Purge()
	}
}

// ----------------------------------//
// Error Handling //
// ---------------------------------//
var (
	// Permanent errors
	ErrConnectionForciblyClosedPermanent = errkit.New("connection forcibly closed by remote host").
						SetKind(errkit.ErrKindNetworkPermanent).
						Build()

	// Temporary errors
	ErrConnectionForciblyClosedTemp = errkit.New("connection forcibly closed by remote host").
					SetKind(errkit.ErrKindNetworkTemporary).
					Build()
	ErrTLSHandshakeTemp = errkit.New("tls handshake error").
				SetKind(errkit.ErrKindNetworkTemporary).
				Build()
	ErrProxyTemp = errkit.New("proxy connection error").
			SetKind(errkit.ErrKindNetworkTemporary).
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
		maxErrors:        10,
		maxErrorDuration: 1 * time.Minute,
	}
}

// HandleError processes errors and determines if they're permanent
func (h *ErrorHandler) HandleError(err error, host string) error {
	if err == nil {
		return nil
	}

	// Get the error as errkit.ErrorX
	errx := errkit.FromError(err)

	// If it's already permanent, return as is
	if errx.Kind() == errkit.ErrKindNetworkPermanent {
		return errx
	}

	// Only handle temporary errors
	if errx.Kind() == errkit.ErrKindNetworkTemporary {
		now := time.Now()

		errorCount, _ := h.hostErrors.GetIFPresent(host)
		errorCount++
		_ = h.hostErrors.Set(host, errorCount)

		lastTime, _ := h.lastErrorTime.GetIFPresent(host)

		// Check if we're within the error window
		if !lastTime.IsZero() && now.Sub(lastTime) <= h.maxErrorDuration {
			if errorCount >= h.maxErrors {
				// Convert to permanent error
				errx.ResetKind().SetKind(errkit.ErrKindNetworkPermanent)
				return errkit.WithMessagef(errx.Build(),
					"max errors (%d) reached within %v for host %s",
					h.maxErrors, h.maxErrorDuration, host)
			}
		} else {
			// Reset counter if we're outside the window
			errorCount = 1
			_ = h.hostErrors.Set(host, errorCount)
		}

		// Update last error time
		_ = h.lastErrorTime.Set(host, now)
	}

	return errx.Build()
}

// Purge cleans up the caches
func (h *ErrorHandler) Purge() {
	h.hostErrors.Purge()
	h.lastErrorTime.Purge()
}
