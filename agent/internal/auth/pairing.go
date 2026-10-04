package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/montygulzar/sentinel-remote-operator/agent/internal/audit"
)

// Pairing failure reasons.
var (
	ErrNoPairingSession = errors.New("no active pairing session")
	ErrPairingExpired   = errors.New("pairing session expired")
	ErrPairingAttempts  = errors.New("pairing session cancelled after too many attempts")
	ErrPairingBadNonce  = errors.New("missing or invalid device nonce")
)

const (
	// CurrentProtocolVersion is the Operator<->Sentinel protocol version
	// recorded on each paired device for future compatibility handling.
	CurrentProtocolVersion = 1

	pairingCodeBytes   = 16 // 128-bit pairing code: infeasible to guess
	maxPairingAttempts = 5
	pairingNonceScope  = "pair"

	labelDeviceKey   = "sentinel/device-key/v1"
	labelPairConfirm = "sentinel/pair-confirm/v1"
)

// pairingCodeEncoding renders the random code as uppercase base32 without
// padding, which is unambiguous to type/scan. The encoded string itself is used
// as the HMAC key, so its full entropy is preserved.
var pairingCodeEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// PairRequest is the body an Operator sends to complete pairing.
type PairRequest struct {
	DisplayName string `json:"displayName"`
	// DeviceNonce is base64-encoded random bytes contributed by the Operator to
	// the device-key derivation.
	DeviceNonce string `json:"deviceNonce"`
}

// PairResult is returned to the Operator on successful pairing. It carries no
// secret: the device key is derived independently on both sides from the
// pairing code and the two nonces, and is never transmitted. AgentProof lets
// the Operator confirm the agent also knew the code before trusting the result.
type PairResult struct {
	DeviceID        string `json:"deviceId"`
	AgentNonce      string `json:"agentNonce"`
	AgentProof      string `json:"agentProof"`
	ProtocolVersion int    `json:"protocolVersion"`
}

type pairingSession struct {
	code      string
	expiresAt time.Time
	attempts  int
}

// PairingManager owns the single, owner-initiated, short-lived pairing window
// and completes pairing requests. It is safe for concurrent use; completion is
// serialized so a session is consumed exactly once.
type PairingManager struct {
	registry *Registry
	log      *audit.Logger
	ttl      time.Duration
	skew     time.Duration
	now      func() time.Time
	nonces   *nonceCache

	mu      sync.Mutex
	session *pairingSession
}

// NewPairingManager builds a PairingManager. ttl is the pairing-window
// lifetime; skew is the request timestamp tolerance (shared with request auth).
func NewPairingManager(registry *Registry, log *audit.Logger, ttl, skew time.Duration) *PairingManager {
	return newPairingManager(registry, log, ttl, skew, time.Now)
}

func newPairingManager(registry *Registry, log *audit.Logger, ttl, skew time.Duration, now func() time.Time) *PairingManager {
	return &PairingManager{
		registry: registry,
		log:      log,
		ttl:      ttl,
		skew:     skew,
		now:      now,
		nonces:   newNonceCache(skew, now),
	}
}

// Start opens a pairing window and returns the one-time code to show the owner,
// replacing any previous window. The code is never logged; only the fact that
// pairing opened and when it expires is audited.
func (m *PairingManager) Start() (code string, expiresAt time.Time, err error) {
	raw, err := randomBytes(pairingCodeBytes)
	if err != nil {
		return "", time.Time{}, err
	}
	code = pairingCodeEncoding.EncodeToString(raw)
	expiresAt = m.now().Add(m.ttl)

	m.mu.Lock()
	m.session = &pairingSession{code: code, expiresAt: expiresAt}
	m.mu.Unlock()

	m.log.Log(audit.ClassSecurity, "pairing session opened, expires %s", expiresAt.UTC().Format(time.RFC3339))
	return code, expiresAt, nil
}

// Cancel closes any open pairing window.
func (m *PairingManager) Cancel() {
	m.mu.Lock()
	had := m.session != nil
	m.session = nil
	m.mu.Unlock()
	if had {
		m.log.Log(audit.ClassSecurity, "pairing session cancelled")
	}
}

// Active reports whether a pairing window is currently open and unexpired.
func (m *PairingManager) Active() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.session != nil && !m.now().After(m.session.expiresAt)
}

// Complete verifies a pairing request (signed with the pairing code) and, on
// success, registers a new device and returns the confirmation material. The
// session is single-use: a successful completion consumes it, and a replayed or
// repeated request cannot pair a second device. Repeated bad-code attempts
// cancel the window.
func (m *PairingManager) Complete(r SignedRequest, sig string, req PairRequest) (PairResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s := m.session
	if s == nil {
		return PairResult{}, ErrNoPairingSession
	}
	if m.now().After(s.expiresAt) {
		m.session = nil
		m.log.Log(audit.ClassSecurity, "pairing attempt rejected: session expired")
		return PairResult{}, ErrPairingExpired
	}

	if err := verifySigned([]byte(s.code), r, sig, m.skew, m.now(), m.nonces, pairingNonceScope); err != nil {
		if errors.Is(err, ErrBadSignature) {
			s.attempts++
			if s.attempts >= maxPairingAttempts {
				m.session = nil
				m.log.Log(audit.ClassSecurity, "pairing session cancelled after too many invalid attempts")
				return PairResult{}, ErrPairingAttempts
			}
		}
		m.log.Log(audit.ClassSecurity, "pairing attempt rejected: %v", err)
		return PairResult{}, err
	}

	deviceNonce, err := base64.StdEncoding.DecodeString(req.DeviceNonce)
	if err != nil || len(deviceNonce) == 0 {
		m.log.Log(audit.ClassSecurity, "pairing attempt rejected: bad device nonce")
		return PairResult{}, ErrPairingBadNonce
	}
	agentNonce, err := randomBytes(16)
	if err != nil {
		return PairResult{}, err
	}
	id, err := newID()
	if err != nil {
		return PairResult{}, err
	}

	deviceKey := deriveDeviceKey([]byte(s.code), agentNonce, deviceNonce)
	proof := derivePairConfirm([]byte(s.code), id, agentNonce, deviceNonce)

	name := req.DisplayName
	if name == "" {
		name = "Operator"
	}
	now := m.now()
	dev := &Device{
		ID:              id,
		DisplayName:     name,
		Key:             deviceKey,
		CreatedAt:       now,
		LastSeenAt:      now,
		ProtocolVersion: CurrentProtocolVersion,
	}
	if err := m.registry.Add(dev); err != nil {
		return PairResult{}, err
	}

	m.session = nil // single use
	m.log.Log(audit.ClassSecurity, "DEVICE_PAIRED id=%s name=%q", id, name)

	return PairResult{
		DeviceID:        id,
		AgentNonce:      base64.StdEncoding.EncodeToString(agentNonce),
		AgentProof:      base64.StdEncoding.EncodeToString(proof),
		ProtocolVersion: CurrentProtocolVersion,
	}, nil
}

// deriveDeviceKey computes the permanent device key from the pairing code and
// both nonces. Because it is a function of the shared code and public nonces,
// agent and Operator derive the identical key without ever transmitting it.
func deriveDeviceKey(code, agentNonce, deviceNonce []byte) []byte {
	return mac(code, labelDeviceKey, nil, agentNonce, deviceNonce)
}

// derivePairConfirm computes the agent's proof-of-code, binding the assigned
// device id so the Operator can confirm it is talking to the real agent.
func derivePairConfirm(code []byte, deviceID string, agentNonce, deviceNonce []byte) []byte {
	return mac(code, labelPairConfirm, []byte(deviceID), agentNonce, deviceNonce)
}

func mac(key []byte, label string, extra, agentNonce, deviceNonce []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(label))
	h.Write(extra)
	h.Write(agentNonce)
	h.Write(deviceNonce)
	return h.Sum(nil)
}

// DeriveDeviceKey is the Operator-side counterpart of the agent's key
// derivation, exported so a client (and the tests) can reproduce the exact
// permanent device key from the pairing code and the nonces.
func DeriveDeviceKey(code string, agentNonceB64, deviceNonceB64 string) ([]byte, error) {
	an, err := base64.StdEncoding.DecodeString(agentNonceB64)
	if err != nil {
		return nil, err
	}
	dn, err := base64.StdEncoding.DecodeString(deviceNonceB64)
	if err != nil {
		return nil, err
	}
	return deriveDeviceKey([]byte(code), an, dn), nil
}

// DerivePairConfirm is the Operator-side counterpart used to verify the agent's
// proof returned in PairResult.
func DerivePairConfirm(code, deviceID, agentNonceB64, deviceNonceB64 string) ([]byte, error) {
	an, err := base64.StdEncoding.DecodeString(agentNonceB64)
	if err != nil {
		return nil, err
	}
	dn, err := base64.StdEncoding.DecodeString(deviceNonceB64)
	if err != nil {
		return nil, err
	}
	return derivePairConfirm([]byte(code), deviceID, an, dn), nil
}
