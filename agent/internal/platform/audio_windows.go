//go:build windows

package platform

import (
	"fmt"
	"math"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// audioEndpoint controls the default output device's master volume and mute via
// the Windows Core Audio IAudioEndpointVolume interface. It holds no COM state:
// each operation sets up and tears down COM on its own OS-locked thread, because
// COM apartments are per-thread and Go goroutines migrate between threads. This
// is slightly more work per call but is correct and keeps the type trivially
// safe for concurrent use.
type audioEndpoint struct{}

func newAudioEndpoint() *audioEndpoint { return &audioEndpoint{} }

// Core Audio class and interface identifiers.
var (
	clsidMMDeviceEnumerator = windows.GUID{Data1: 0xBCDE0395, Data2: 0xE52F, Data3: 0x467C,
		Data4: [8]byte{0x8E, 0x3D, 0xC4, 0x57, 0x92, 0x91, 0x69, 0x2E}}
	iidIMMDeviceEnumerator = windows.GUID{Data1: 0xA95664D2, Data2: 0x9614, Data3: 0x4F35,
		Data4: [8]byte{0xA7, 0x46, 0xDE, 0x8D, 0xB6, 0x36, 0x17, 0xE6}}
	iidIAudioEndpointVolume = windows.GUID{Data1: 0x5CDF2C82, Data2: 0x841E, Data3: 0x4546,
		Data4: [8]byte{0x97, 0x22, 0x0C, 0xF7, 0x40, 0x78, 0x22, 0x9A}}
)

var (
	modole32             = windows.NewLazySystemDLL("ole32.dll")
	procCoInitializeEx   = modole32.NewProc("CoInitializeEx")
	procCoUninitialize   = modole32.NewProc("CoUninitialize")
	procCoCreateInstance = modole32.NewProc("CoCreateInstance")
)

const (
	coinitMultithreaded = 0x0
	clsctxAll           = 0x17
	eRender             = 0 // output devices
	eConsole            = 0 // default role for games/system sounds
)

// Vtable slot indices (counting the inherited IUnknown methods at 0..2).
const (
	slotRelease                    = 2
	slotGetDefaultAudioEndpoint    = 4  // IMMDeviceEnumerator
	slotActivate                   = 3  // IMMDevice
	slotSetMasterVolumeLevelScalar = 7  // IAudioEndpointVolume
	slotSetMute                    = 14 // IAudioEndpointVolume
)

func (a *audioEndpoint) setMuted(muted bool) error {
	return a.withEndpointVolume(func(epv unsafe.Pointer) error {
		var b uintptr
		if muted {
			b = 1
		}
		return hresult("SetMute", comCall(epv, slotSetMute, b, 0))
	})
}

func (a *audioEndpoint) setVolume(percent int) error {
	if percent < 0 || percent > 100 {
		return fmt.Errorf("volume percent %d out of range 0..100", percent)
	}
	level := math.Float32bits(float32(percent) / 100)
	return a.withEndpointVolume(func(epv unsafe.Pointer) error {
		// level is the 2nd argument; on amd64 asmstdcall mirrors it into XMM1,
		// so the float is received correctly by the native method.
		return hresult("SetMasterVolumeLevelScalar", comCall(epv, slotSetMasterVolumeLevelScalar, uintptr(level), 0))
	})
}

// withEndpointVolume runs fn with an activated IAudioEndpointVolume for the
// default output device, handling COM lifetime on a dedicated thread. COM
// interface handles are kept as unsafe.Pointer (not uintptr) so the vtable
// dispatch is GC-safe and vet-clean.
func (a *audioEndpoint) withEndpointVolume(fn func(epv unsafe.Pointer) error) (err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if hr, _, _ := procCoInitializeEx.Call(0, coinitMultithreaded); failed(hr) {
		return fmt.Errorf("CoInitializeEx: hresult 0x%x", uint32(hr))
	}
	defer procCoUninitialize.Call()

	var enumerator unsafe.Pointer
	hr, _, _ := procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsidMMDeviceEnumerator)),
		0,
		clsctxAll,
		uintptr(unsafe.Pointer(&iidIMMDeviceEnumerator)),
		uintptr(unsafe.Pointer(&enumerator)),
	)
	if failed(hr) {
		return fmt.Errorf("CoCreateInstance(MMDeviceEnumerator): hresult 0x%x", uint32(hr))
	}
	defer comCall(enumerator, slotRelease)

	var device unsafe.Pointer
	if hr := comCall(enumerator, slotGetDefaultAudioEndpoint, eRender, eConsole, uintptr(unsafe.Pointer(&device))); failed(hr) {
		return fmt.Errorf("GetDefaultAudioEndpoint: hresult 0x%x", uint32(hr))
	}
	defer comCall(device, slotRelease)

	var epv unsafe.Pointer
	if hr := comCall(device, slotActivate,
		uintptr(unsafe.Pointer(&iidIAudioEndpointVolume)),
		clsctxAll, 0, uintptr(unsafe.Pointer(&epv))); failed(hr) {
		return fmt.Errorf("Activate(IAudioEndpointVolume): hresult 0x%x", uint32(hr))
	}
	defer comCall(epv, slotRelease)

	return fn(epv)
}

const ptrSize = unsafe.Sizeof(uintptr(0))

// comCall invokes the method at vtable slot on a COM interface pointer. iface
// points at the object; its first word is the vtable, an array of method
// addresses.
func comCall(iface unsafe.Pointer, slot int, args ...uintptr) uintptr {
	vtbl := *(*unsafe.Pointer)(iface)
	fn := *(*uintptr)(unsafe.Add(vtbl, uintptr(slot)*ptrSize))
	call := make([]uintptr, 0, len(args)+1)
	call = append(call, uintptr(iface))
	call = append(call, args...)
	ret, _, _ := syscall.SyscallN(fn, call...)
	return ret
}

// failed reports whether an HRESULT indicates failure (high bit set).
func failed(hr uintptr) bool { return int32(hr) < 0 }

func hresult(op string, hr uintptr) error {
	if failed(hr) {
		return fmt.Errorf("%s: hresult 0x%x", op, uint32(hr))
	}
	return nil
}
