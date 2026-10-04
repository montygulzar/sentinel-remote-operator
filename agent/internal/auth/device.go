package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Device is an authorized Operator device (spec §13 authorized-device model).
// Key is the per-device HMAC secret held in memory; it is never serialized in
// the clear (the on-disk form is protected) and never logged or returned by any
// API.
type Device struct {
	ID              string
	DisplayName     string
	Key             []byte
	CreatedAt       time.Time
	LastSeenAt      time.Time
	RevokedAt       *time.Time
	ProtocolVersion int
}

// Enabled reports whether the device may still authenticate.
func (d Device) Enabled() bool { return d.RevokedAt == nil }

// Info is the secret-free projection of a Device, safe to return from list
// endpoints and the CLI. It deliberately omits Key.
type Info struct {
	ID              string     `json:"id"`
	DisplayName     string     `json:"displayName"`
	CreatedAt       time.Time  `json:"createdAt"`
	LastSeenAt      *time.Time `json:"lastSeenAt"`
	RevokedAt       *time.Time `json:"revokedAt"`
	Enabled         bool       `json:"enabled"`
	ProtocolVersion int        `json:"protocolVersion"`
}

func (d Device) info() Info {
	var lastSeen *time.Time
	if !d.LastSeenAt.IsZero() {
		t := d.LastSeenAt
		lastSeen = &t
	}
	return Info{
		ID:              d.ID,
		DisplayName:     d.DisplayName,
		CreatedAt:       d.CreatedAt,
		LastSeenAt:      lastSeen,
		RevokedAt:       d.RevokedAt,
		Enabled:         d.Enabled(),
		ProtocolVersion: d.ProtocolVersion,
	}
}

// deviceRecord is the on-disk form; the key is protected then base64-encoded.
type deviceRecord struct {
	ID              string     `json:"id"`
	DisplayName     string     `json:"displayName"`
	Key             string     `json:"key"`
	CreatedAt       time.Time  `json:"createdAt"`
	LastSeenAt      time.Time  `json:"lastSeenAt"`
	RevokedAt       *time.Time `json:"revokedAt"`
	ProtocolVersion int        `json:"protocolVersion"`
}

type registryFile struct {
	Devices []deviceRecord `json:"devices"`
}

// Registry is the authorized-device registry: a concurrency-safe, persistent
// collection of Operator devices. Supporting many devices and revoking any one
// of them are first-class operations, so adding a second device later needs no
// redesign (spec §13).
type Registry struct {
	path      string
	protector Protector

	mu      sync.RWMutex
	devices map[string]*Device
}

// OpenRegistry loads the registry from path, decrypting each device key with p.
// A missing file yields an empty registry (first run).
func OpenRegistry(path string, p Protector) (*Registry, error) {
	r := &Registry{path: path, protector: p, devices: make(map[string]*Device)}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}

	var rf registryFile
	if err := json.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("parse registry %s: %w", path, err)
	}
	for _, rec := range rf.Devices {
		blob, err := base64.StdEncoding.DecodeString(rec.Key)
		if err != nil {
			return nil, fmt.Errorf("decode key for device %s: %w", rec.ID, err)
		}
		key, err := p.Unprotect(blob)
		if err != nil {
			return nil, fmt.Errorf("unprotect key for device %s: %w", rec.ID, err)
		}
		r.devices[rec.ID] = &Device{
			ID:              rec.ID,
			DisplayName:     rec.DisplayName,
			Key:             key,
			CreatedAt:       rec.CreatedAt,
			LastSeenAt:      rec.LastSeenAt,
			RevokedAt:       rec.RevokedAt,
			ProtocolVersion: rec.ProtocolVersion,
		}
	}
	return r, nil
}

// Add inserts a new device and persists the registry.
func (r *Registry) Add(d *Device) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.devices[d.ID]; exists {
		return fmt.Errorf("device %s already exists", d.ID)
	}
	r.devices[d.ID] = d
	return r.saveLocked()
}

// Get returns a copy of the device with the given id. The copy's Key is a
// distinct slice so callers cannot mutate registry state.
func (r *Registry) Get(id string) (Device, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.devices[id]
	if !ok {
		return Device{}, false
	}
	cp := *d
	cp.Key = append([]byte(nil), d.Key...)
	return cp, true
}

// List returns the secret-free info for all devices, ordered by creation time
// then id for stable output.
func (r *Registry) List() []Info {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Info, 0, len(r.devices))
	for _, d := range r.devices {
		out = append(out, d.info())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

// Count returns the number of registered devices.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.devices)
}

// Revoke marks a device revoked as of now and persists immediately, so the next
// authentication attempt from it fails. It returns whether the device was
// found. Revoking an already-revoked device is a no-op success.
func (r *Registry) Revoke(id string, now time.Time) (found bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.devices[id]
	if !ok {
		return false, nil
	}
	if d.RevokedAt != nil {
		return true, nil
	}
	t := now
	d.RevokedAt = &t
	return true, r.saveLocked()
}

// Touch records that a device was just seen. LastSeenAt is informational and
// kept in memory; it is persisted on the next structural change or on Save.
func (r *Registry) Touch(id string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if d, ok := r.devices[id]; ok {
		d.LastSeenAt = now
	}
}

// Save persists the current registry state.
func (r *Registry) Save() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.saveLocked()
}

func (r *Registry) saveLocked() error {
	rf := registryFile{}
	for _, d := range r.devices {
		blob, err := r.protector.Protect(d.Key)
		if err != nil {
			return err
		}
		rf.Devices = append(rf.Devices, deviceRecord{
			ID:              d.ID,
			DisplayName:     d.DisplayName,
			Key:             base64.StdEncoding.EncodeToString(blob),
			CreatedAt:       d.CreatedAt,
			LastSeenAt:      d.LastSeenAt,
			RevokedAt:       d.RevokedAt,
			ProtocolVersion: d.ProtocolVersion,
		})
	}
	sort.Slice(rf.Devices, func(i, j int) bool {
		if rf.Devices[i].CreatedAt.Equal(rf.Devices[j].CreatedAt) {
			return rf.Devices[i].ID < rf.Devices[j].ID
		}
		return rf.Devices[i].CreatedAt.Before(rf.Devices[j].CreatedAt)
	})

	if err := os.MkdirAll(filepath.Dir(r.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(r.path, append(data, '\n'), 0o600)
}
