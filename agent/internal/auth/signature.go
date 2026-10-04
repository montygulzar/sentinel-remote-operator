package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Header names carrying the authentication material on every request.
const (
	HeaderDevice    = "X-Sentinel-Device"
	HeaderTimestamp = "X-Sentinel-Timestamp"
	HeaderNonce     = "X-Sentinel-Nonce"
	HeaderSignature = "X-Sentinel-Signature"
)

// SignedRequest is the set of request attributes covered by the signature.
// Binding method, path, timestamp, nonce and a hash of the body means a signed
// request cannot be redirected to a different endpoint, reused, or tampered
// with in transit without detection.
type SignedRequest struct {
	DeviceID string
	Method   string
	// Path is the full request target: URL path plus any query string (e.g.
	// "/v1/logs?limit=50"). Signing the whole target means query parameters are
	// authenticated, not just the path.
	Path      string
	Timestamp string // unix seconds as decimal text
	Nonce     string
	Body      []byte
}

// canonical builds the exact byte string that is HMAC'd. Fields are joined with
// newlines; the body is reduced to its SHA-256 hex digest so large bodies do
// not have to be buffered twice and empty bodies hash deterministically.
func (r SignedRequest) canonical() string {
	bodyHash := sha256.Sum256(r.Body)
	return strings.Join([]string{
		r.DeviceID,
		strings.ToUpper(r.Method),
		r.Path,
		r.Timestamp,
		r.Nonce,
		hex.EncodeToString(bodyHash[:]),
	}, "\n")
}

// Signature returns the HMAC-SHA256 signature of the request under key, as
// lowercase hex.
func Signature(key []byte, r SignedRequest) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(r.canonical()))
	return hex.EncodeToString(mac.Sum(nil))
}

// equalSignature compares two hex signatures in constant time.
func equalSignature(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}
