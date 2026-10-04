//go:build !windows

package auth

// noopProtector is the non-Windows Protector. Sentinel is a Windows product;
// this exists so the agent builds and is testable during development. It does
// not encrypt — secrets are protected only by file permissions — so it must
// not be relied on in production.
type noopProtector struct{}

// NewProtector returns the platform Protector. On non-Windows builds it is the
// development no-op.
func NewProtector() Protector { return noopProtector{} }

func (noopProtector) Protect(plain []byte) ([]byte, error) {
	return append([]byte(nil), plain...), nil
}

func (noopProtector) Unprotect(blob []byte) ([]byte, error) {
	return append([]byte(nil), blob...), nil
}
