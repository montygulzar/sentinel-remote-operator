package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// randomBytes returns n cryptographically-random bytes.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// newID returns a short, stable, URL-safe random identifier for a device.
func newID() (string, error) {
	b, err := randomBytes(9)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// EnsureSecret loads the protected secret at path, or generates an n-byte
// secret, protects it and writes it (owner-only), returning whether it was
// newly created. It is used for the owner/admin key: a local bootstrap secret
// that is stored encrypted at rest and only ever used to sign admin requests —
// never transmitted and never logged. Agent and CLI share it by reading the
// same path with the same Protector.
func EnsureSecret(path string, p Protector, n int) (secret []byte, created bool, err error) {
	data, err := os.ReadFile(path)
	if err == nil {
		blob, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if derr != nil {
			return nil, false, fmt.Errorf("decode secret %s: %w", path, derr)
		}
		secret, derr = p.Unprotect(blob)
		if derr != nil {
			return nil, false, fmt.Errorf("unprotect secret %s: %w", path, derr)
		}
		return secret, false, nil
	}
	if !os.IsNotExist(err) {
		return nil, false, err
	}

	secret, err = randomBytes(n)
	if err != nil {
		return nil, false, err
	}
	if err := saveProtected(path, p, secret); err != nil {
		return nil, false, err
	}
	return secret, true, nil
}

func saveProtected(path string, p Protector, secret []byte) error {
	blob, err := p.Protect(secret)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(blob)+"\n"), 0o600)
}
