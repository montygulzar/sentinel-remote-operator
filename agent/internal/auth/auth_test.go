package auth

import (
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// testRegistry returns a registry backed by a temp file and a device with a
// known key registered in it.
func testRegistry(t *testing.T) (*Registry, Device) {
	t.Helper()
	reg, err := OpenRegistry(filepath.Join(t.TempDir(), "devices.json"), NewProtector())
	if err != nil {
		t.Fatalf("OpenRegistry: %v", err)
	}
	key, _ := randomBytes(32)
	now := time.Unix(1_700_000_000, 0)
	dev := &Device{ID: "dev-1", DisplayName: "iPhone", Key: key, CreatedAt: now, LastSeenAt: now, ProtocolVersion: 1}
	if err := reg.Add(dev); err != nil {
		t.Fatalf("Add: %v", err)
	}
	return reg, *dev
}

func signedFor(dev Device, method, path string, body []byte, nonce string, now time.Time) (SignedRequest, string) {
	r := SignedRequest{
		DeviceID:  dev.ID,
		Method:    method,
		Path:      path,
		Timestamp: strconv.FormatInt(now.Unix(), 10),
		Nonce:     nonce,
		Body:      body,
	}
	return r, Signature(dev.Key, r)
}

func authAt(reg *Registry, now time.Time) *Authenticator {
	admin, _ := randomBytes(32)
	return newAuthenticator(reg, admin, 30*time.Second, func() time.Time { return now })
}

func TestVerifyDeviceAcceptsValid(t *testing.T) {
	reg, dev := testRegistry(t)
	now := time.Unix(1_700_000_100, 0)
	a := authAt(reg, now)

	r, sig := signedFor(dev, "POST", "/v1/control/lock", nil, "n1", now)
	if _, err := a.VerifyDevice(r, sig); err != nil {
		t.Fatalf("valid device request rejected: %v", err)
	}
}

func TestVerifyDeviceUnknown(t *testing.T) {
	reg, dev := testRegistry(t)
	now := time.Unix(1_700_000_100, 0)
	a := authAt(reg, now)

	r, sig := signedFor(dev, "GET", "/v1/status", nil, "n1", now)
	r.DeviceID = "ghost"
	if _, err := a.VerifyDevice(r, sig); err != ErrUnknownDevice {
		t.Fatalf("got %v, want ErrUnknownDevice", err)
	}
}

func TestVerifyDeviceTamperRejected(t *testing.T) {
	reg, dev := testRegistry(t)
	now := time.Unix(1_700_000_100, 0)

	cases := map[string]func(*SignedRequest){
		"method": func(r *SignedRequest) { r.Method = "DELETE" },
		"path":   func(r *SignedRequest) { r.Path = "/v1/control/shutdown" },
		"body":   func(r *SignedRequest) { r.Body = []byte(`{"muted":false}`) },
		"nonce":  func(r *SignedRequest) { r.Nonce = "other" },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			a := authAt(reg, now)
			r, sig := signedFor(dev, "POST", "/v1/control/mute", []byte(`{"muted":true}`), "n1", now)
			tamper(&r)
			if _, err := a.VerifyDevice(r, sig); err != ErrBadSignature {
				t.Fatalf("tampered %s: got %v, want ErrBadSignature", name, err)
			}
		})
	}
}

func TestVerifyDeviceStale(t *testing.T) {
	reg, dev := testRegistry(t)
	signTime := time.Unix(1_700_000_100, 0)
	a := authAt(reg, signTime.Add(31*time.Second))

	r, sig := signedFor(dev, "GET", "/v1/status", nil, "n1", signTime)
	if _, err := a.VerifyDevice(r, sig); err != ErrStaleTimestamp {
		t.Fatalf("got %v, want ErrStaleTimestamp", err)
	}
}

func TestVerifyDeviceReplay(t *testing.T) {
	reg, dev := testRegistry(t)
	now := time.Unix(1_700_000_100, 0)
	a := authAt(reg, now)

	r, sig := signedFor(dev, "POST", "/v1/control/lock", nil, "once", now)
	if _, err := a.VerifyDevice(r, sig); err != nil {
		t.Fatalf("first use rejected: %v", err)
	}
	if _, err := a.VerifyDevice(r, sig); err != ErrReplayed {
		t.Fatalf("replay: got %v, want ErrReplayed", err)
	}
}

func TestVerifyDeviceRevokedImmediately(t *testing.T) {
	reg, dev := testRegistry(t)
	now := time.Unix(1_700_000_100, 0)
	a := authAt(reg, now)

	// Works before revocation.
	r, sig := signedFor(dev, "GET", "/v1/status", nil, "n1", now)
	if _, err := a.VerifyDevice(r, sig); err != nil {
		t.Fatalf("pre-revoke rejected: %v", err)
	}
	// Revoke, then the very next request fails.
	if found, err := reg.Revoke(dev.ID, now); !found || err != nil {
		t.Fatalf("Revoke: found=%v err=%v", found, err)
	}
	r2, sig2 := signedFor(dev, "GET", "/v1/status", nil, "n2", now)
	if _, err := a.VerifyDevice(r2, sig2); err != ErrRevoked {
		t.Fatalf("post-revoke: got %v, want ErrRevoked", err)
	}
}

func TestMultipleDevicesAreIsolated(t *testing.T) {
	reg, devA := testRegistry(t)
	now := time.Unix(1_700_000_100, 0)
	keyB, _ := randomBytes(32)
	devB := &Device{ID: "dev-2", DisplayName: "iPad", Key: keyB, CreatedAt: now, LastSeenAt: now, ProtocolVersion: 1}
	if err := reg.Add(devB); err != nil {
		t.Fatalf("Add B: %v", err)
	}
	a := authAt(reg, now)

	// Each device authenticates with its own key.
	rA, sigA := signedFor(devA, "GET", "/v1/status", nil, "a1", now)
	if _, err := a.VerifyDevice(rA, sigA); err != nil {
		t.Fatalf("device A rejected: %v", err)
	}
	rB, sigB := signedFor(*devB, "GET", "/v1/status", nil, "b1", now)
	if _, err := a.VerifyDevice(rB, sigB); err != nil {
		t.Fatalf("device B rejected: %v", err)
	}
	// A signature claiming to be B but signed with A's key is rejected.
	forged := SignedRequest{DeviceID: devB.ID, Method: "GET", Path: "/v1/status",
		Timestamp: strconv.FormatInt(now.Unix(), 10), Nonce: "x", Body: nil}
	if _, err := a.VerifyDevice(forged, Signature(devA.Key, forged)); err != ErrBadSignature {
		t.Fatalf("cross-device forgery: got %v, want ErrBadSignature", err)
	}
	// Revoking B leaves A working.
	reg.Revoke(devB.ID, now)
	rA2, sigA2 := signedFor(devA, "GET", "/v1/status", nil, "a2", now)
	if _, err := a.VerifyDevice(rA2, sigA2); err != nil {
		t.Fatalf("device A broke after revoking B: %v", err)
	}
}

func TestConcurrentReplayExactlyOneWins(t *testing.T) {
	reg, dev := testRegistry(t)
	now := time.Unix(1_700_000_100, 0)
	a := authAt(reg, now)

	r, sig := signedFor(dev, "POST", "/v1/control/lock", nil, "race-nonce", now)

	const n = 64
	var wg sync.WaitGroup
	results := make(chan error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := a.VerifyDevice(r, sig)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if err != ErrReplayed {
			t.Fatalf("unexpected error under race: %v", err)
		}
	}
	if success != 1 {
		t.Fatalf("expected exactly one successful auth, got %d", success)
	}
}

func TestVerifyAdmin(t *testing.T) {
	reg, _ := testRegistry(t)
	now := time.Unix(1_700_000_100, 0)
	admin, _ := randomBytes(32)
	a := newAuthenticator(reg, admin, 30*time.Second, func() time.Time { return now })

	r := SignedRequest{DeviceID: "admin", Method: "GET", Path: "/v1/admin/devices",
		Timestamp: strconv.FormatInt(now.Unix(), 10), Nonce: "adm1", Body: nil}
	if err := a.VerifyAdmin(r, Signature(admin, r)); err != nil {
		t.Fatalf("valid admin rejected: %v", err)
	}
	// Wrong key rejected.
	wrong, _ := randomBytes(32)
	if err := a.VerifyAdmin(r, Signature(wrong, r)); err != ErrBadSignature {
		t.Fatalf("bad admin key: got %v, want ErrBadSignature", err)
	}
}

func TestRegistryPersistRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	reg, err := OpenRegistry(path, NewProtector())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	key, _ := randomBytes(32)
	now := time.Unix(1_700_000_100, 0)
	rev := now.Add(time.Hour)
	reg.Add(&Device{ID: "d1", DisplayName: "A", Key: key, CreatedAt: now, LastSeenAt: now, ProtocolVersion: 1})
	reg.Add(&Device{ID: "d2", DisplayName: "B", Key: key, CreatedAt: now.Add(time.Minute), ProtocolVersion: 1, RevokedAt: &rev})

	reopened, err := OpenRegistry(path, NewProtector())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if reopened.Count() != 2 {
		t.Fatalf("want 2 devices after reload, got %d", reopened.Count())
	}
	d1, ok := reopened.Get("d1")
	if !ok || string(d1.Key) != string(key) || !d1.Enabled() {
		t.Fatalf("d1 did not round-trip: %+v ok=%v", d1, ok)
	}
	d2, _ := reopened.Get("d2")
	if d2.Enabled() {
		t.Fatalf("d2 should be revoked after reload")
	}
}
