package api

import (
	"bytes"
	"io"
	"net"
	"net/http"

	"github.com/montygulzar/sentinel-remote-operator/agent/internal/audit"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/auth"
)

// maxBodyBytes caps request bodies. The control surface takes only small JSON
// payloads; a hard cap prevents a client from forcing the agent to buffer
// unbounded data to compute the body hash.
const maxBodyBytes = 1 << 20 // 1 MiB

// readSigned reads the (bounded) body once and assembles the SignedRequest from
// the request line and Sentinel headers. The body is returned separately so it
// can be restored for the handler after verification. Path uses RequestURI so
// the query string is covered by the signature.
func (s *Server) readSigned(w http.ResponseWriter, r *http.Request) (auth.SignedRequest, []byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeReject(w, http.StatusRequestEntityTooLarge, "request body too large")
		return auth.SignedRequest{}, nil, false
	}
	sr := auth.SignedRequest{
		DeviceID:  r.Header.Get(auth.HeaderDevice),
		Method:    r.Method,
		Path:      r.URL.RequestURI(),
		Timestamp: r.Header.Get(auth.HeaderTimestamp),
		Nonce:     r.Header.Get(auth.HeaderNonce),
		Body:      body,
	}
	return sr, body, true
}

// deviceAuth wraps h so the request must carry a valid signature from a known,
// non-revoked Operator device. Any failure is logged for the Sentinel security
// stream and rejected with an opaque 401.
func (s *Server) deviceAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sr, body, ok := s.readSigned(w, r)
		if !ok {
			return
		}
		if _, err := s.auth.VerifyDevice(sr, r.Header.Get(auth.HeaderSignature)); err != nil {
			s.log.Log(audit.ClassSecurity, "device auth rejected for %s %s: %v", r.Method, r.URL.Path, err)
			writeReject(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		h(w, r)
	}
}

// adminAuth wraps h so the request must come from the local machine (unless
// disabled) and carry a valid admin-key signature. The loopback check is a
// conservative default so pairing and revocation cannot be driven remotely even
// if the admin key leaked (spec §13: deliberate owner initiation).
func (s *Server) adminAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.adminLoopbackOnly && !isLoopback(r.RemoteAddr) {
			s.log.Log(audit.ClassSecurity, "admin request from non-loopback %s rejected", r.RemoteAddr)
			writeReject(w, http.StatusForbidden, "forbidden")
			return
		}
		sr, body, ok := s.readSigned(w, r)
		if !ok {
			return
		}
		if err := s.auth.VerifyAdmin(sr, r.Header.Get(auth.HeaderSignature)); err != nil {
			s.log.Log(audit.ClassSecurity, "admin auth rejected for %s %s: %v", r.Method, r.URL.Path, err)
			writeReject(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		h(w, r)
	}
}

// isLoopback reports whether remoteAddr (host:port) is a loopback address.
func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
