package auth

// Protector encrypts secrets at rest. On Windows it wraps DPAPI
// (CryptProtectData, local-machine scope) so credential material is never
// stored as plaintext; on other platforms it is a development no-op and
// secrets rely on owner-only (0600) file permissions. Both are selected at
// build time by NewProtector.
type Protector interface {
	Protect(plain []byte) ([]byte, error)
	Unprotect(blob []byte) ([]byte, error)
}
