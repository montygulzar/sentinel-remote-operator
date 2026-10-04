// Package auth implements Sentinel's device authorization and request
// authentication (spec §13).
//
// Every state-changing or data-returning request is signed with a per-device
// shared secret using HMAC-SHA256 over a canonical representation of the
// request (see signature.go). Authorization is never granted on network
// membership or possession of an address alone: a valid signature over a fresh
// (non-replayed, unexpired) request from a known, non-revoked device is
// required for every call.
//
// Authorized Operator devices live in a Registry; owner/admin operations
// (pairing, listing, revocation) authenticate with a separate admin key. New
// devices join through the pairing flow (pairing.go), which never transmits or
// logs the permanent device key.
package auth

import (
	"errors"
	"strconv"
	"time"
)

// Authentication failure reasons. They are deliberately coarse and the API
// layer maps every one to a single opaque 401, so a caller cannot learn which
// check failed. They remain distinct here for precise audit logging and tests.
var (
	ErrUnknownDevice  = errors.New("unknown device")
	ErrRevoked        = errors.New("device revoked")
	ErrBadSignature   = errors.New("invalid signature")
	ErrStaleTimestamp = errors.New("timestamp outside acceptance window")
	ErrReplayed       = errors.New("nonce already used")
	ErrMalformed      = errors.New("malformed authentication headers")
)

// verifySigned runs the signature, timestamp-skew and nonce-replay checks that
// are common to device and admin authentication and to pairing. The order is
// security-critical: the signature is checked first, so an attacker who does
// not hold the key can neither consume nor probe the nonce cache. The nonce is
// consumed last and atomically, so it is spent only for an otherwise-valid
// request.
//
// nonceScope namespaces the nonce cache so that distinct principals (each
// device, the admin key, the pairing channel) cannot collide or interfere with
// one another's replay protection.
func verifySigned(key []byte, r SignedRequest, sig string, skew time.Duration, now time.Time, nonces *nonceCache, nonceScope string) error {
	if r.Timestamp == "" || r.Nonce == "" || sig == "" {
		return ErrMalformed
	}

	expected := Signature(key, r)
	if !equalSignature(expected, sig) {
		return ErrBadSignature
	}

	tsSecs, err := strconv.ParseInt(r.Timestamp, 10, 64)
	if err != nil {
		return ErrMalformed
	}
	delta := now.Sub(time.Unix(tsSecs, 0))
	if delta < 0 {
		delta = -delta
	}
	if delta > skew {
		return ErrStaleTimestamp
	}

	if !nonces.use(nonceScope + "\x00" + r.Nonce) {
		return ErrReplayed
	}
	return nil
}
