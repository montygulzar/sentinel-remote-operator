package api

import (
	"bytes"
	"io"
	"net/http"

	"github.com/montygulzar/sentinel-remote-operator/agent/internal/audit"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/auth"
)

// maxBodyBytes caps request bodies. The M1 surface takes only small JSON
// payloads; a hard cap prevents an authenticated-or-not client from forcing the
// agent to buffer unbounded data to compute the body hash.
const maxBodyBytes = 1 << 20 // 1 MiB

// authenticated wraps h so that every request must carry a valid Sentinel
// signature (spec §13). The body is read once here (bounded) so it can be both
// hashed for verification and handed to the handler; on any failure the request
// is rejected with a generic 401 that does not reveal which check failed.
func (s *Server) authenticated(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			writeReject(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}

		signed := auth.SignedRequest{
			DeviceID: r.Header.Get(auth.HeaderDevice),
			Method:   r.Method,
			// RequestURI covers path AND query so query parameters (e.g. the
			// logs filter) are authenticated and cannot be tampered with in
			// transit.
			Path:      r.URL.RequestURI(),
			Timestamp: r.Header.Get(auth.HeaderTimestamp),
			Nonce:     r.Header.Get(auth.HeaderNonce),
			Body:      body,
		}
		if verr := s.verifier.Verify(signed, r.Header.Get(auth.HeaderSignature)); verr != nil {
			// Log the failure for the Sentinel security event stream (spec §9),
			// but return an opaque message so a caller cannot distinguish an
			// unknown device from a bad signature from a replay.
			s.log.Log(audit.ClassSecurity, "auth rejected for %s %s: %v", r.Method, r.URL.Path, verr)
			writeReject(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		// Make the already-read body available to the handler.
		r.Body = io.NopCloser(bytes.NewReader(body))
		h(w, r)
	}
}
