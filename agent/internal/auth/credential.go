// Package auth implements Sentinel's request authentication (spec §13).
//
// Every API request is signed with a per-device shared secret using
// HMAC-SHA256 over a canonical representation of the request. Authorisation is
// never granted on network membership or possession of an address alone
// (spec §13); a valid signature over a fresh (non-replayed, unexpired) request
// is required for every call.
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Credential is a paired device's identity and shared secret.
type Credential struct {
	DeviceID string `json:"deviceId"`
	// Key is the raw HMAC secret. It is marshalled as base64 and must never be
	// written to the audit log or any diagnostic output.
	Key []byte `json:"key"`
}

// credentialJSON is the on-disk form with the key base64-encoded.
type credentialJSON struct {
	DeviceID string `json:"deviceId"`
	Key      string `json:"key"`
}

func (c Credential) MarshalJSON() ([]byte, error) {
	return json.Marshal(credentialJSON{DeviceID: c.DeviceID, Key: base64.StdEncoding.EncodeToString(c.Key)})
}

func (c *Credential) UnmarshalJSON(data []byte) error {
	var raw credentialJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	key, err := base64.StdEncoding.DecodeString(raw.Key)
	if err != nil {
		return fmt.Errorf("decode credential key: %w", err)
	}
	c.DeviceID = raw.DeviceID
	c.Key = key
	return nil
}

// FileStore persists a single device credential as a restrictive-permission
// JSON file. On Windows this path lives under the protected ProgramData tree;
// a DPAPI-backed store can be slotted in behind the same Load/Ensure surface in
// a later milestone (spec §13) without changing callers.
type FileStore struct{ path string }

// NewFileStore returns a credential store backed by path.
func NewFileStore(path string) *FileStore { return &FileStore{path: path} }

// Load reads the stored credential. It returns os.ErrNotExist (wrapped) if the
// agent has not yet been provisioned.
func (s *FileStore) Load() (Credential, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return Credential{}, err
	}
	var cred Credential
	if err := json.Unmarshal(data, &cred); err != nil {
		return Credential{}, fmt.Errorf("parse credential %s: %w", s.path, err)
	}
	if cred.DeviceID == "" || len(cred.Key) == 0 {
		return Credential{}, fmt.Errorf("credential %s is incomplete", s.path)
	}
	return cred, nil
}

// Save writes cred with owner-only permissions.
func (s *FileStore) Save(cred Credential) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, append(data, '\n'), 0o600)
}

// Ensure loads the existing credential, or generates and persists a new one if
// none exists. It returns the credential and whether it was newly created.
func (s *FileStore) Ensure() (Credential, bool, error) {
	cred, err := s.Load()
	if err == nil {
		return cred, false, nil
	}
	if !os.IsNotExist(err) {
		return Credential{}, false, err
	}
	cred, err = GenerateCredential()
	if err != nil {
		return Credential{}, false, err
	}
	if err := s.Save(cred); err != nil {
		return Credential{}, false, err
	}
	return cred, true, nil
}

// GenerateCredential creates a credential with a random device ID and a 256-bit
// secret drawn from the cryptographic RNG.
func GenerateCredential() (Credential, error) {
	id := make([]byte, 9)
	if _, err := rand.Read(id); err != nil {
		return Credential{}, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return Credential{}, err
	}
	return Credential{
		DeviceID: base64.RawURLEncoding.EncodeToString(id),
		Key:      key,
	}, nil
}
