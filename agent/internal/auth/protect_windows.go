//go:build windows

package auth

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dpapiProtector protects secrets with the Windows Data Protection API
// (DPAPI). Local-machine scope is used so the agent — which runs as a Windows
// service, potentially under a service account distinct from the owner — can
// decrypt its own stored credentials across restarts. The protected blob is
// bound to this machine and cannot be decrypted on another.
type dpapiProtector struct{}

// NewProtector returns the Windows DPAPI-backed Protector.
func NewProtector() Protector { return dpapiProtector{} }

var (
	modcrypt32        = windows.NewLazySystemDLL("crypt32.dll")
	modkernel32dpapi  = windows.NewLazySystemDLL("kernel32.dll")
	procCryptProtect  = modcrypt32.NewProc("CryptProtectData")
	procCryptUnprot   = modcrypt32.NewProc("CryptUnprotectData")
	procLocalFreeBlob = modkernel32dpapi.NewProc("LocalFree")
)

// dataBlob mirrors the Win32 DATA_BLOB structure.
type dataBlob struct {
	cbData uint32
	pbData *byte
}

const cryptProtectLocalMachine = 0x4

func (dpapiProtector) Protect(plain []byte) ([]byte, error) {
	return dpapiCall(procCryptProtect, plain)
}

func (dpapiProtector) Unprotect(blob []byte) ([]byte, error) {
	return dpapiCall(procCryptUnprot, blob)
}

// dpapiCall invokes CryptProtectData/CryptUnprotectData, which share an
// argument layout: (pDataIn, descr/ppszDescr, pEntropy, reserved, prompt,
// flags, pDataOut). The output blob is allocated by the API and freed with
// LocalFree.
func dpapiCall(proc *windows.LazyProc, in []byte) ([]byte, error) {
	var inBlob dataBlob
	if len(in) > 0 {
		inBlob.cbData = uint32(len(in))
		inBlob.pbData = &in[0]
	}
	var out dataBlob
	r1, _, err := proc.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, 0, 0, 0,
		cryptProtectLocalMachine,
		uintptr(unsafe.Pointer(&out)),
	)
	if r1 == 0 {
		return nil, fmt.Errorf("dpapi: %w", err)
	}
	defer procLocalFreeBlob.Call(uintptr(unsafe.Pointer(out.pbData)))

	result := make([]byte, out.cbData)
	copy(result, unsafe.Slice(out.pbData, out.cbData))
	return result, nil
}
