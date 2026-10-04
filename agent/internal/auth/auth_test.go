package auth

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// signed builds a SignedRequest and its signature at time now under key.
func signed(cred Credential, method, path string, body []byte, nonce string, now time.Time) (SignedRequest, string) {
	r := SignedRequest{
		DeviceID:  cred.DeviceID,
		Method:    method,
		Path:      path,
		Timestamp: strconv.FormatInt(now.Unix(), 10),
		Nonce:     nonce,
		Body:      body,
	}
	return r, Signature(cred.Key, r)
}

func testVerifier(t *testing.T, cred Credential, now time.Time) *Verifier {
	t.Helper()
	return newVerifier(cred, 30*time.Second, func() time.Time { return now })
}

func TestVerifyAcceptsValidRequest(t *testing.T) {
	cred, _ := GenerateCredential()
	now := time.Unix(1_700_000_000, 0)
	v := testVerifier(t, cred, now)

	r, sig := signed(cred, "POST", "/v1/control/lock", nil, "n1", now)
	if err := v.Verify(r, sig); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
}

func TestVerifyRejectsUnknownDevice(t *testing.T) {
	cred, _ := GenerateCredential()
	now := time.Unix(1_700_000_000, 0)
	v := testVerifier(t, cred, now)

	r, sig := signed(cred, "GET", "/v1/status", nil, "n1", now)
	r.DeviceID = "someone-else"
	if err := v.Verify(r, sig); err != ErrUnknownDevice {
		t.Fatalf("got %v, want ErrUnknownDevice", err)
	}
}

func TestVerifyRejectsTamperedFields(t *testing.T) {
	cred, _ := GenerateCredential()
	now := time.Unix(1_700_000_000, 0)

	cases := map[string]func(r *SignedRequest){
		"method": func(r *SignedRequest) { r.Method = "DELETE" },
		"path":   func(r *SignedRequest) { r.Path = "/v1/control/shutdown" },
		"body":   func(r *SignedRequest) { r.Body = []byte(`{"muted":false}`) },
		"nonce":  func(r *SignedRequest) { r.Nonce = "different" },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			v := testVerifier(t, cred, now)
			r, sig := signed(cred, "POST", "/v1/control/mute", []byte(`{"muted":true}`), "n1", now)
			tamper(&r)
			if err := v.Verify(r, sig); err != ErrBadSignature {
				t.Fatalf("tampered %s: got %v, want ErrBadSignature", name, err)
			}
		})
	}
}

func TestVerifyRejectsStaleTimestamp(t *testing.T) {
	cred, _ := GenerateCredential()
	signTime := time.Unix(1_700_000_000, 0)
	// Verifier's clock is 31s ahead of the signature — outside the 30s window.
	v := testVerifier(t, cred, signTime.Add(31*time.Second))

	r, sig := signed(cred, "GET", "/v1/status", nil, "n1", signTime)
	if err := v.Verify(r, sig); err != ErrStaleTimestamp {
		t.Fatalf("got %v, want ErrStaleTimestamp", err)
	}
}

func TestVerifyRejectsReplay(t *testing.T) {
	cred, _ := GenerateCredential()
	now := time.Unix(1_700_000_000, 0)
	v := testVerifier(t, cred, now)

	r, sig := signed(cred, "POST", "/v1/control/lock", nil, "nonce-once", now)
	if err := v.Verify(r, sig); err != nil {
		t.Fatalf("first use rejected: %v", err)
	}
	if err := v.Verify(r, sig); err != ErrReplayed {
		t.Fatalf("replay: got %v, want ErrReplayed", err)
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	cred, _ := GenerateCredential()
	now := time.Unix(1_700_000_000, 0)
	v := testVerifier(t, cred, now)

	r, sig := signed(cred, "GET", "/v1/status", nil, "", now) // empty nonce
	if err := v.Verify(r, sig); err != ErrMalformed {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}

func TestFileStoreEnsurePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.json")
	store := NewFileStore(path)

	cred, created, err := store.Ensure()
	if err != nil || !created {
		t.Fatalf("first Ensure: created=%v err=%v", created, err)
	}
	if len(cred.Key) != 32 || cred.DeviceID == "" {
		t.Fatalf("weak credential generated: %+v", cred)
	}

	// File must be owner-only.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("credential perms = %o, want 600", perm)
	}

	// Second Ensure loads the same credential, does not regenerate.
	again, created, err := store.Ensure()
	if err != nil || created {
		t.Fatalf("second Ensure: created=%v err=%v", created, err)
	}
	if again.DeviceID != cred.DeviceID || string(again.Key) != string(cred.Key) {
		t.Fatalf("credential changed across loads")
	}
}
