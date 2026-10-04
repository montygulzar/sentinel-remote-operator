package auth

import "time"

// Authenticator verifies signed requests for the two classes of principal:
// authorized Operator devices (looked up in the Registry) and the owner/admin
// key. It enforces signature validity, timestamp skew and nonce-replay
// protection, with independent nonce scopes per principal. It is safe for
// concurrent use.
type Authenticator struct {
	registry *Registry
	adminKey []byte
	skew     time.Duration
	now      func() time.Time

	deviceNonces *nonceCache
	adminNonces  *nonceCache
}

// NewAuthenticator builds an Authenticator. skew is the maximum accepted
// age/future-dating of a signed request.
func NewAuthenticator(registry *Registry, adminKey []byte, skew time.Duration) *Authenticator {
	return newAuthenticator(registry, adminKey, skew, time.Now)
}

func newAuthenticator(registry *Registry, adminKey []byte, skew time.Duration, now func() time.Time) *Authenticator {
	return &Authenticator{
		registry:     registry,
		adminKey:     adminKey,
		skew:         skew,
		now:          now,
		deviceNonces: newNonceCache(skew, now),
		adminNonces:  newNonceCache(skew, now),
	}
}

// VerifyDevice authenticates a request from an Operator device. An unknown
// device id, a revoked device, a bad signature, a stale timestamp or a replayed
// nonce all fail. A revoked device fails before the nonce is consumed, so
// revocation takes effect immediately and cannot be used to exhaust the nonce
// cache. On success the device's last-seen time is updated and the device is
// returned.
func (a *Authenticator) VerifyDevice(r SignedRequest, sig string) (Device, error) {
	if r.DeviceID == "" {
		return Device{}, ErrMalformed
	}
	dev, ok := a.registry.Get(r.DeviceID)
	if !ok {
		return Device{}, ErrUnknownDevice
	}
	if !dev.Enabled() {
		return Device{}, ErrRevoked
	}
	if err := verifySigned(dev.Key, r, sig, a.skew, a.now(), a.deviceNonces, "dev:"+dev.ID); err != nil {
		return Device{}, err
	}
	a.registry.Touch(dev.ID, a.now())
	return dev, nil
}

// VerifyAdmin authenticates an owner/admin request against the admin key.
func (a *Authenticator) VerifyAdmin(r SignedRequest, sig string) error {
	return verifySigned(a.adminKey, r, sig, a.skew, a.now(), a.adminNonces, "admin")
}
