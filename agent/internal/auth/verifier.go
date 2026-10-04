package auth

import (
	"errors"
	"strconv"
	"time"
)

// Verification failure reasons. They are deliberately coarse: the agent must
// not leak which specific check failed to an unauthenticated caller, so the API
// layer maps every one of these to a single 401 response.
var (
	ErrUnknownDevice  = errors.New("unknown device")
	ErrBadSignature   = errors.New("invalid signature")
	ErrStaleTimestamp = errors.New("timestamp outside acceptance window")
	ErrReplayed       = errors.New("nonce already used")
	ErrMalformed      = errors.New("malformed authentication headers")
)

// Verifier authenticates signed requests against a single paired credential and
// enforces timestamp skew and nonce-replay protection. It is safe for
// concurrent use.
type Verifier struct {
	cred   Credential
	skew   time.Duration
	now    func() time.Time
	nonces *nonceCache
}

// NewVerifier builds a Verifier for cred. skew is the maximum allowed age or
// future-dating of a request timestamp.
func NewVerifier(cred Credential, skew time.Duration) *Verifier {
	return newVerifier(cred, skew, time.Now)
}

func newVerifier(cred Credential, skew time.Duration, now func() time.Time) *Verifier {
	return &Verifier{
		cred:   cred,
		skew:   skew,
		now:    now,
		nonces: newNonceCache(skew, now),
	}
}

// Verify checks a request's authentication material. The order is chosen so
// that the expensive/stateful checks (nonce consumption) run only after the
// signature proves the caller holds the key: an attacker without the key can
// neither exhaust the nonce cache nor probe for valid nonces.
func (v *Verifier) Verify(r SignedRequest, signature string) error {
	if r.DeviceID == "" || r.Timestamp == "" || r.Nonce == "" || signature == "" {
		return ErrMalformed
	}
	if r.DeviceID != v.cred.DeviceID {
		return ErrUnknownDevice
	}

	expected := Signature(v.cred.Key, r)
	if !equalSignature(expected, signature) {
		return ErrBadSignature
	}

	// Signature is valid: the timestamp is now trustworthy and bound to the key.
	tsSecs, err := strconv.ParseInt(r.Timestamp, 10, 64)
	if err != nil {
		return ErrMalformed
	}
	delta := v.now().Sub(time.Unix(tsSecs, 0))
	if delta < 0 {
		delta = -delta
	}
	if delta > v.skew {
		return ErrStaleTimestamp
	}

	if !v.nonces.use(r.Nonce) {
		return ErrReplayed
	}
	return nil
}
