package rawhttp

import (
	"io"
	"time"

	GB403Logger "github.com/slicingmelon/gobypass403/core/utils/logger"
	"github.com/valyala/fasthttp"
)

// RawTransport implements the RoundTripper interface
type RawTransport struct{}

// RoundTrip implements the RoundTripper interface
func (t *RawTransport) RoundTrip(hc *fasthttp.HostClient, req *fasthttp.Request, resp *fasthttp.Response) (retry bool, err error) {
	customSkipBody := resp.SkipBody
	customStreamBody := resp.StreamBody

	var deadline time.Time
	if req.GetTimeOut() > 0 {
		deadline = time.Now().Add(req.GetTimeOut())
	}

	// Acquire connection from host client
	cc, err := hc.AcquireConn(req.GetTimeOut(), req.ConnectionClose())
	if err != nil {
		return false, err
	}

	// Get the underlying net.Conn from clientConn
	conn := cc.Conn()

	writeDeadline := deadline
	if hc.WriteTimeout > 0 {
		tmpWriteDeadline := time.Now().Add(hc.WriteTimeout)
		if writeDeadline.IsZero() || tmpWriteDeadline.Before(writeDeadline) {
			writeDeadline = tmpWriteDeadline
		}
	}

	if err = conn.SetWriteDeadline(writeDeadline); err != nil {
		hc.CloseConn(cc)
		return true, err
	}

	resetConnection := false
	if hc.MaxConnDuration > 0 && time.Since(cc.CreatedTime()) > hc.MaxConnDuration && !req.ConnectionClose() {
		req.SetConnectionClose()
		resetConnection = true
	}

	// Get writer
	bw := hc.AcquireWriter(conn)

	// Just write the raw request body directly
	// The req.Body() function gets the request body, which in our case is the raw HTTP request
	_, err = bw.Write(req.Body())

	if resetConnection {
		req.Header.ResetConnectionClose()
	}

	if err == nil {
		err = bw.Flush()
	}

	// Release the writer
	hc.ReleaseWriter(bw)

	// Return ErrTimeout on any timeout.
	if x, ok := err.(interface{ Timeout() bool }); ok && x.Timeout() {
		err = fasthttp.ErrTimeout
	}

	if err != nil {
		hc.CloseConn(cc)
		return true, err
	}

	readDeadline := deadline
	if hc.ReadTimeout > 0 {
		tmpReadDeadline := time.Now().Add(hc.ReadTimeout)
		if readDeadline.IsZero() || tmpReadDeadline.Before(readDeadline) {
			readDeadline = tmpReadDeadline
		}
	}

	if err = conn.SetReadDeadline(readDeadline); err != nil {
		hc.CloseConn(cc)
		return true, err
	}

	if customSkipBody || req.Header.IsHead() {
		resp.SkipBody = true
	}
	if hc.DisableHeaderNamesNormalizing {
		resp.Header.DisableNormalizing()
	}

	// Use proper method to acquire reader
	br := hc.AcquireReader(conn)

	if GB403Logger.IsDebugEnabled() {
		GB403Logger.Debug().Msgf("Reading response with MaxBodySize: %d", hc.MaxResponseBodySize)
	}

	// Attempt to read the response body
	err = resp.ReadLimitBody(br, hc.MaxResponseBodySize)
	if err != nil {
		hc.ReleaseReader(br)
		hc.CloseConn(cc)

		// Enhanced error logging for debugging
		if GB403Logger.IsDebugEnabled() {
			GB403Logger.Debug().Msgf("ReadLimitBody error type: %T, message: %v", err, err)

			// Check specifically for timeout errors which might be common
			if x, ok := err.(interface{ Timeout() bool }); ok && x.Timeout() {
				GB403Logger.Debug().Msgf("Response read timed out")
			}
		}

		// Don't retry in case of ErrBodyTooLarge since we will just get the same again.
		// Use fasthttp.ErrBodyTooLarge from the imported package to ensure we're comparing
		// against the exact same constant that FastHTTP is using
		needRetry := err != fasthttp.ErrBodyTooLarge

		// Log retry decision
		if GB403Logger.IsDebugEnabled() {
			GB403Logger.Debug().Msgf("ReadLimitBody error: %v, needRetry: %v", err, needRetry)
		}

		return needRetry, err
	}

	// Log successful response
	if GB403Logger.IsDebugEnabled() {
		GB403Logger.Debug().Msgf("Response status: %d, headers: %d, body size: %d",
			resp.StatusCode(), resp.Header.Len(), len(resp.Body()))
	}

	closeConn := resetConnection || req.ConnectionClose() || resp.ConnectionClose()
	if customStreamBody && resp.BodyStream() != nil {
		rbs := resp.BodyStream()
		resp.SetBodyStream(newCloseReaderWithError(rbs, func(wErr error) error {
			hc.ReleaseReader(br)
			if closeConn || resp.ConnectionClose() || wErr != nil {
				hc.CloseConn(cc)
			} else {
				hc.ReleaseConn(cc)
			}
			return nil
		}), -1)
		return false, nil
	}

	hc.ReleaseReader(br)

	if closeConn {
		hc.CloseConn(cc)
	} else {
		hc.ReleaseConn(cc)
	}
	return false, nil
}

// Helper function similar to fasthttp's
func newCloseReaderWithError(r io.Reader, closeFunc func(err error) error) ReadCloserWithError {
	return &closeReader{
		Reader:    r,
		closeFunc: closeFunc,
	}
}

type ReadCloserWithError interface {
	io.Reader
	CloseWithError(err error) error
}

type closeReader struct {
	io.Reader
	closeFunc func(err error) error
}

func (c *closeReader) CloseWithError(err error) error {
	return c.closeFunc(err)
}
