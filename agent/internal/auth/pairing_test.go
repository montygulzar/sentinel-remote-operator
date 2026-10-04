package auth

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/montygulzar/sentinel-remote-operator/agent/internal/audit"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestPairing(t *testing.T) (*PairingManager, *Registry, *audit.Logger, *clock) {
	t.Helper()
	reg, err := OpenRegistry(filepath.Join(t.TempDir(), "devices.json"), NewProtector())
	if err != nil {
		t.Fatalf("OpenRegistry: %v", err)
	}
	log, err := audit.New(t.TempDir(), 0)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	t.Cleanup(func() { log.Close() })
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	m := newPairingManager(reg, log, 5*time.Minute, 30*time.Second, c.now)
	return m, reg, log, c
}

// pairRequest builds a signed pairing request for code with a fresh device
// nonce, returning the request, its signature, the parsed body and the nonce.
func pairRequest(t *testing.T, code, nonce string, now time.Time, displayName string) (SignedRequest, string, PairRequest, string) {
	t.Helper()
	dn, _ := randomBytes(16)
	dnB64 := base64.StdEncoding.EncodeToString(dn)
	req := PairRequest{DisplayName: displayName, DeviceNonce: dnB64}
	body, _ := json.Marshal(req)
	sr := SignedRequest{
		DeviceID:  "pairing",
		Method:    "POST",
		Path:      "/v1/pair",
		Timestamp: strconv.FormatInt(now.Unix(), 10),
		Nonce:     nonce,
		Body:      body,
	}
	return sr, Signature([]byte(code), sr), req, dnB64
}

func TestPairingSuccess(t *testing.T) {
	m, reg, _, c := newTestPairing(t)
	code, _, err := m.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	sr, sig, req, dnB64 := pairRequest(t, code, "p1", c.now(), "iPhone 11 Pro Max")
	res, err := m.Complete(sr, sig, req)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if res.DeviceID == "" || res.ProtocolVersion != CurrentProtocolVersion {
		t.Fatalf("bad result: %+v", res)
	}

	// A device now exists with the key BOTH sides derive independently.
	dev, ok := reg.Get(res.DeviceID)
	if !ok {
		t.Fatalf("device not registered")
	}
	operatorKey, err := DeriveDeviceKey(code, res.AgentNonce, dnB64)
	if err != nil {
		t.Fatalf("DeriveDeviceKey: %v", err)
	}
	if string(operatorKey) != string(dev.Key) {
		t.Fatalf("operator-derived key does not match stored device key")
	}
	// Operator can verify the agent's proof-of-code.
	proof, _ := DerivePairConfirm(code, res.DeviceID, res.AgentNonce, dnB64)
	if base64.StdEncoding.EncodeToString(proof) != res.AgentProof {
		t.Fatalf("agent proof mismatch")
	}
	if dev.DisplayName != "iPhone 11 Pro Max" {
		t.Fatalf("display name not recorded: %q", dev.DisplayName)
	}
}

func TestPairingExpired(t *testing.T) {
	m, _, _, c := newTestPairing(t)
	code, _, _ := m.Start()
	c.t = c.t.Add(6 * time.Minute) // past the 5m TTL

	sr, sig, req, _ := pairRequest(t, code, "p1", c.now(), "late")
	if _, err := m.Complete(sr, sig, req); err != ErrPairingExpired {
		t.Fatalf("got %v, want ErrPairingExpired", err)
	}
}

func TestPairingNoSession(t *testing.T) {
	m, _, _, c := newTestPairing(t)
	sr, sig, req, _ := pairRequest(t, "ABCDEFGHIJKLMNOP", "p1", c.now(), "x")
	if _, err := m.Complete(sr, sig, req); err != ErrNoPairingSession {
		t.Fatalf("got %v, want ErrNoPairingSession", err)
	}
}

func TestPairingWrongCodeAndAttemptCap(t *testing.T) {
	m, reg, _, c := newTestPairing(t)
	m.Start()

	// Each wrong-code attempt uses a distinct nonce so it is the signature, not
	// replay, that fails.
	for i := 0; i < maxPairingAttempts-1; i++ {
		sr, _, req, _ := pairRequest(t, "WRONGCODEWRONGCODE", "w"+strconv.Itoa(i), c.now(), "x")
		if _, err := m.Complete(sr, "deadbeef", req); err != ErrBadSignature {
			t.Fatalf("attempt %d: got %v, want ErrBadSignature", i, err)
		}
	}
	// The final failed attempt trips the cap and cancels the session.
	sr, _, req, _ := pairRequest(t, "WRONGCODEWRONGCODE", "wFinal", c.now(), "x")
	if _, err := m.Complete(sr, "deadbeef", req); err != ErrPairingAttempts {
		t.Fatalf("cap: got %v, want ErrPairingAttempts", err)
	}
	if m.Active() {
		t.Fatalf("session should be cancelled after attempt cap")
	}
	if reg.Count() != 0 {
		t.Fatalf("no device should have been created")
	}
}

func TestPairingSingleUse(t *testing.T) {
	m, reg, _, c := newTestPairing(t)
	code, _, _ := m.Start()

	sr, sig, req, _ := pairRequest(t, code, "p1", c.now(), "first")
	if _, err := m.Complete(sr, sig, req); err != nil {
		t.Fatalf("first complete: %v", err)
	}
	// Session is consumed: a second completion (even with a fresh valid-looking
	// request) cannot pair another device.
	sr2, sig2, req2, _ := pairRequest(t, code, "p2", c.now(), "second")
	if _, err := m.Complete(sr2, sig2, req2); err != ErrNoPairingSession {
		t.Fatalf("second complete: got %v, want ErrNoPairingSession", err)
	}
	if reg.Count() != 1 {
		t.Fatalf("single-use violated: %d devices", reg.Count())
	}
}

func TestPairingReplayWithinSession(t *testing.T) {
	m, _, _, c := newTestPairing(t)
	code, _, _ := m.Start()

	// A valid request whose body has a bad device nonce fails without consuming
	// the session, but consumes its request nonce; replaying the identical
	// signed request is rejected as a replay.
	dnBad := "" // empty -> ErrPairingBadNonce, but signature is valid first
	req := PairRequest{DisplayName: "x", DeviceNonce: dnBad}
	body, _ := json.Marshal(req)
	sr := SignedRequest{DeviceID: "pairing", Method: "POST", Path: "/v1/pair",
		Timestamp: strconv.FormatInt(c.now().Unix(), 10), Nonce: "dup", Body: body}
	sig := Signature([]byte(code), sr)

	if _, err := m.Complete(sr, sig, req); err != ErrPairingBadNonce {
		t.Fatalf("first: got %v, want ErrPairingBadNonce", err)
	}
	if _, err := m.Complete(sr, sig, req); err != ErrReplayed {
		t.Fatalf("replay: got %v, want ErrReplayed", err)
	}
}

func TestPairingAuditsWithoutSecrets(t *testing.T) {
	m, reg, log, c := newTestPairing(t)
	code, _, _ := m.Start()

	sr, sig, req, _ := pairRequest(t, code, "p1", c.now(), "iPhone")
	res, err := m.Complete(sr, sig, req)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	dev, _ := reg.Get(res.DeviceID)
	deviceKeyB64 := base64.StdEncoding.EncodeToString(dev.Key)

	var paired bool
	for _, ev := range log.Recent(0) {
		if strings.Contains(ev.Message, "DEVICE_PAIRED") {
			paired = true
		}
		// No secret material may appear in any audit message.
		if strings.Contains(ev.Message, code) {
			t.Fatalf("pairing code leaked into audit log: %q", ev.Message)
		}
		if strings.Contains(ev.Message, deviceKeyB64) || strings.Contains(ev.Message, res.AgentProof) {
			t.Fatalf("key material leaked into audit log: %q", ev.Message)
		}
	}
	if !paired {
		t.Fatalf("DEVICE_PAIRED event not audited")
	}
}
