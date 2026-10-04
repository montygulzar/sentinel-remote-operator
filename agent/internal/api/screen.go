package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/montygulzar/sentinel-remote-operator/agent/internal/audit"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/platform"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/screen"
)

// Metadata headers on a successful Grab Screen response. The image itself is
// the binary body (spec §15 prefers a binary image with metadata headers over a
// large base64 blob in JSON), so the client reads capture details from here.
const (
	headerCaptureDisplay   = "X-Sentinel-Capture-Display"
	headerCaptureWidth     = "X-Sentinel-Capture-Width"
	headerCaptureHeight    = "X-Sentinel-Capture-Height"
	headerCaptureFormat    = "X-Sentinel-Capture-Format"
	headerCaptureTimestamp = "X-Sentinel-Capture-Timestamp" // unix seconds
	headerCaptureMs        = "X-Sentinel-Capture-Ms"        // host grab time
	headerEncodeMs         = "X-Sentinel-Encode-Ms"         // encode time
)

// handleScreenGrab captures one current frame of a display and returns it as a
// binary image with capture metadata in headers (spec §5 GRAB SCREEN, §11
// capture→memory→encode→transmit→discard). The frame is never written to disk:
// it is encoded straight from memory into the response and then dropped. A
// capture that the host cannot perform — including a surface the OS protects —
// is reported honestly as a non-2xx rejection rather than a blank success.
func (s *Server) handleScreenGrab(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	format, err := screen.ParseFormat(q.Get("format"))
	if err != nil {
		writeReject(w, http.StatusBadRequest, err.Error())
		return
	}
	quality := 0 // 0 means "use the server default" in screen.Encode
	if raw := q.Get("quality"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			writeReject(w, http.StatusBadRequest, "quality must be an integer in 1..100")
			return
		}
		quality = n
	}
	displayID := q.Get("display")

	s.log.Log(audit.ClassScreen, "Grab Screen requested")

	frame, err := s.provider.CaptureFrame(displayID)
	if err != nil {
		s.log.Log(audit.ClassError, "Grab Screen capture failed: %v", err)
		switch {
		case errors.Is(err, platform.ErrNoSuchDisplay):
			writeReject(w, http.StatusNotFound, "no such display")
		case errors.Is(err, platform.ErrUnavailable):
			writeReject(w, http.StatusServiceUnavailable, "screen capture unavailable on this host")
		default:
			writeReject(w, http.StatusServiceUnavailable, "screen capture failed")
		}
		return
	}

	encodeStart := time.Now()
	data, err := screen.Encode(frame.Image, format, quality)
	if err != nil {
		s.log.Log(audit.ClassError, "Grab Screen encode failed: %v", err)
		writeReject(w, http.StatusInternalServerError, "could not encode captured frame")
		return
	}
	encodeMs := time.Since(encodeStart).Milliseconds()

	// Record the capture without ever logging its pixels (spec §12).
	s.log.Log(audit.ClassScreen, "Grab Screen delivered display=%s %dx%d %s %dB",
		frame.DisplayID, frame.Width, frame.Height, format, len(data))

	h := w.Header()
	h.Set("Content-Type", format.ContentType())
	h.Set("Content-Length", strconv.Itoa(len(data)))
	// The frame is ephemeral owner data; do not let any intermediary cache it.
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set(headerCaptureDisplay, frame.DisplayID)
	h.Set(headerCaptureWidth, strconv.Itoa(frame.Width))
	h.Set(headerCaptureHeight, strconv.Itoa(frame.Height))
	h.Set(headerCaptureFormat, string(format))
	h.Set(headerCaptureTimestamp, strconv.FormatInt(frame.CapturedAt.Unix(), 10))
	h.Set(headerCaptureMs, strconv.FormatInt(frame.CaptureMs, 10))
	h.Set(headerEncodeMs, strconv.FormatInt(encodeMs, 10))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
