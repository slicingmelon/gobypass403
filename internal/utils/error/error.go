package error

import (
	"errors"
	"sync"

	"github.com/VictoriaMetrics/fastcache"
	"github.com/valyala/fasthttp"
)

// Enhanced ErrorHandler
type ErrorHandler struct {
	cache     *fastcache.Cache
	maxErrors uint32
	stats     ErrorStats
	hostStats map[string]*HostStats
	mu        sync.RWMutex
}

type GoBypass403Error uint8

const (
	ErrNone GoBypass403Error = iota
)

// General errors
var (
	ErrGracefulShutdown = errors.New("graceful shutdown initiated")
	ErrNotRunning       = errors.New("scanner is not running")
	ErrScannerExited    = errors.New("scanner exited unexpectedly")
)

// HTTP/Connection errors
var (
	ErrTooManyTimeouts    = errors.New("too many timeout errors for host")
	ErrTooManyConnections = errors.New("too many connection errors for host")
	ErrTooManyRequests    = errors.New("too many requests for host")
	ErrHostUnreachable    = errors.New("host became unreachable")
)

// TLS errors
var (
	ErrTLSHandshake       = errors.New("TLS handshake failed")
	ErrInvalidCertificate = errors.New("invalid certificate")
)

// Payload errors
var (
	ErrInvalidPayload  = errors.New("invalid payload format")
	ErrPayloadTooLarge = errors.New("payload exceeds maximum size")
	ErrEmptyPayload    = errors.New("empty payload provided")
)

// Response errors
var (
	ErrInvalidResponse = errors.New("invalid response received")
	ErrEmptyResponse   = errors.New("empty response received")
	ErrResponseTimeout = errors.New("response timeout")
)

// Scanner errors
var (
	ErrBypassFailed = errors.New("bypass attempt failed")
)

func (h *ErrorHandler) HandleError(host string, err error) error {
	if err == nil {
		return nil
	}

	hostKey := []byte(host)
	count := h.incrementErrorCount(hostKey)

	if count >= h.maxErrors {
		var newErr error
		switch err {
		case fasthttp.ErrTimeout:
			newErr = ErrTooManyTimeouts
		case fasthttp.ErrConnectionClosed:
			newErr = ErrTooManyConnections
		case fasthttp.ErrNoFreeConns:
			newErr = ErrHostUnreachable
		default:
			newErr = ErrBypassFailed
		}
		h.RecordError(host, newErr, 0)
		return newErr
	}

	return err
}

// IsTemporaryError checks if the error is temporary
func IsTemporaryError(err error) bool {
	return errors.Is(err, ErrTooManyTimeouts) ||
		errors.Is(err, ErrTooManyRequests) ||
		errors.Is(err, ErrResponseTimeout)
}

func IsPermanentError(err error) bool {
	return errors.Is(err, ErrHostUnreachable) ||
		errors.Is(err, ErrTLSHandshake) ||
		errors.Is(err, ErrInvalidCertificate)
}
