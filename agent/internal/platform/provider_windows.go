//go:build windows

package platform

import (
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// winProvider is the real Windows host implementation of Provider. It uses only
// documented Win32 APIs and never touches OS privacy, audit or security
// controls (spec §2, §18). Metrics that an API reports as unknown are returned
// as nil pointers so the Operator shows UNAVAILABLE rather than a guessed value.
type winProvider struct {
	deviceName string
	audio      *audioEndpoint
}

// New returns the Windows host Provider.
func New(deviceName string) Provider {
	if deviceName == "" {
		if h, err := os.Hostname(); err == nil {
			deviceName = h
		} else {
			deviceName = "UNKNOWN"
		}
	}
	return &winProvider{deviceName: deviceName, audio: newAudioEndpoint()}
}

func (p *winProvider) DeviceName() string { return p.deviceName }

// Lazy-loaded system DLLs and procedures. NewLazySystemDLL resolves from the
// system directory only, avoiding DLL search-order hijacking.
var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	moduser32   = windows.NewLazySystemDLL("user32.dll")

	procGetTickCount64     = modkernel32.NewProc("GetTickCount64")
	procGetTickCount       = modkernel32.NewProc("GetTickCount")
	procGlobalMemoryStatus = modkernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemPower     = modkernel32.NewProc("GetSystemPowerStatus")
	procGetSystemTimes     = modkernel32.NewProc("GetSystemTimes")

	procLockWorkStation     = moduser32.NewProc("LockWorkStation")
	procGetLastInputInfo    = moduser32.NewProc("GetLastInputInfo")
	procGetForegroundWindow = moduser32.NewProc("GetForegroundWindow")
	procGetWindowThreadPID  = moduser32.NewProc("GetWindowThreadProcessId")
	procEnumWindows         = moduser32.NewProc("EnumWindows")
	procPostMessageW        = moduser32.NewProc("PostMessageW")
	procOpenInputDesktop    = moduser32.NewProc("OpenInputDesktop")
	procGetUserObjectInfo   = moduser32.NewProc("GetUserObjectInformationW")
	procCloseDesktop        = moduser32.NewProc("CloseDesktop")
)

type lastInputInfo struct {
	cbSize uint32
	dwTime uint32
}

type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

type systemPowerStatus struct {
	ACLineStatus        byte
	BatteryFlag         byte
	BatteryLifePercent  byte
	SystemStatusFlag    byte
	BatteryLifeTime     uint32
	BatteryFullLifeTime uint32
}

type filetime struct {
	low  uint32
	high uint32
}

func (f filetime) uint64() uint64 { return uint64(f.high)<<32 | uint64(f.low) }

const wmClose = 0x0010

func (p *winProvider) System() (SystemInfo, error) {
	info := SystemInfo{DeviceName: p.deviceName, Session: p.sessionState()}
	if idle, ok := p.idleSeconds(); ok {
		info.IdleSeconds = &idle
	}
	if up, ok := p.uptimeSeconds(); ok {
		info.UptimeSeconds = &up
	}
	if ram, ok := p.ramPercent(); ok {
		info.RAMPercent = &ram
	}
	if bat, ok := p.batteryPercent(); ok {
		info.BatteryPercent = &bat
	}
	if cpu, ok := p.cpuPercent(); ok {
		info.CPUPercent = &cpu
	}
	return info, nil
}

func (p *winProvider) Activity() (Activity, error) {
	act := Activity{Session: p.sessionState()}
	if idle, ok := p.idleSeconds(); ok {
		act.IdleSeconds = &idle
	}
	if app, ok := p.foregroundApp(); ok {
		act.ActiveApp = &app
	}
	return act, nil
}

func (p *winProvider) Lock() error {
	r1, _, err := procLockWorkStation.Call()
	if r1 == 0 {
		return err
	}
	return nil
}

func (p *winProvider) SetVolume(percent int) error { return p.audio.setVolume(percent) }
func (p *winProvider) SetMuted(muted bool) error   { return p.audio.setMuted(muted) }

// idleSeconds returns seconds since the last local user input. The tick values
// are 32-bit and wrap roughly every 49 days; unsigned subtraction stays correct
// across a single wrap.
func (p *winProvider) idleSeconds() (int64, bool) {
	lii := lastInputInfo{cbSize: uint32(unsafe.Sizeof(lastInputInfo{}))}
	r1, _, _ := procGetLastInputInfo.Call(uintptr(unsafe.Pointer(&lii)))
	if r1 == 0 {
		return 0, false
	}
	now, _, _ := procGetTickCount.Call()
	idleMs := uint32(now) - lii.dwTime
	return int64(idleMs / 1000), true
}

func (p *winProvider) uptimeSeconds() (int64, bool) {
	ms, _, _ := procGetTickCount64.Call()
	return int64(uint64(ms) / 1000), true
}

func (p *winProvider) ramPercent() (int, bool) {
	ms := memoryStatusEx{dwLength: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	r1, _, _ := procGlobalMemoryStatus.Call(uintptr(unsafe.Pointer(&ms)))
	if r1 == 0 {
		return 0, false
	}
	return int(ms.dwMemoryLoad), true
}

func (p *winProvider) batteryPercent() (int, bool) {
	var sps systemPowerStatus
	r1, _, _ := procGetSystemPower.Call(uintptr(unsafe.Pointer(&sps)))
	if r1 == 0 || sps.BatteryLifePercent == 255 {
		return 0, false // 255 == unknown (e.g. desktop with no battery)
	}
	return int(sps.BatteryLifePercent), true
}

// cpuPercent samples system times across a short interval and computes busy
// percentage. The brief sleep is acceptable for an on-demand status call and
// avoids carrying mutable sampling state in the provider.
func (p *winProvider) cpuPercent() (int, bool) {
	idle0, total0, ok := p.systemTimes()
	if !ok {
		return 0, false
	}
	time.Sleep(200 * time.Millisecond)
	idle1, total1, ok := p.systemTimes()
	if !ok {
		return 0, false
	}
	totalDelta := total1 - total0
	idleDelta := idle1 - idle0
	if totalDelta == 0 {
		return 0, false
	}
	busy := float64(totalDelta-idleDelta) / float64(totalDelta) * 100
	return clampPercent(int(busy + 0.5)), true
}

// systemTimes returns cumulative idle and total (kernel+user; kernel already
// includes idle) tick counts.
func (p *winProvider) systemTimes() (idle, total uint64, ok bool) {
	var ftIdle, ftKernel, ftUser filetime
	r1, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&ftIdle)),
		uintptr(unsafe.Pointer(&ftKernel)),
		uintptr(unsafe.Pointer(&ftUser)),
	)
	if r1 == 0 {
		return 0, 0, false
	}
	return ftIdle.uint64(), ftKernel.uint64() + ftUser.uint64(), true
}

// sessionState reports lock state by inspecting the current input desktop. When
// the session is locked the input desktop is the secure "Winlogon" desktop and
// is not openable from an interactive process. This is a best-effort
// synchronous probe; precise, event-driven lock tracking is Milestone 5. Any
// uncertainty is reported as SessionUnknown rather than guessed.
func (p *winProvider) sessionState() SessionState {
	const desktopReadObjects = 0x0001
	h, _, _ := procOpenInputDesktop.Call(0, 0, uintptr(desktopReadObjects))
	if h == 0 {
		// Cannot open the input desktop: typically the secure desktop (locked).
		return SessionLocked
	}
	defer procCloseDesktop.Call(h)

	const uoiName = 2
	var buf [256]uint16
	var needed uint32
	r1, _, _ := procGetUserObjectInfo.Call(
		h, uintptr(uoiName),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)*2),
		uintptr(unsafe.Pointer(&needed)),
	)
	if r1 == 0 {
		return SessionUnknown
	}
	name := windows.UTF16ToString(buf[:])
	if strings.EqualFold(name, "Default") {
		return SessionUnlocked
	}
	return SessionLocked
}

func (p *winProvider) foregroundApp() (string, bool) {
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == 0 {
		return "", false
	}
	var pid uint32
	procGetWindowThreadPID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	if pid == 0 {
		return "", false
	}
	name, ok := processImageName(pid)
	if !ok {
		return "", false
	}
	return name, true
}

// CloseApp posts WM_CLOSE to every top-level window owned by a process whose
// executable base name matches name (case-insensitive). WM_CLOSE is a graceful
// request — the app runs its normal shutdown — rather than a forced
// termination. Matching no running app is not an error (Provider contract).
func (p *winProvider) CloseApp(name string) error {
	target := strings.ToLower(name)
	cb := windows.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		var pid uint32
		procGetWindowThreadPID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		if pid == 0 {
			return 1 // continue enumeration
		}
		if img, ok := processImageName(pid); ok && strings.ToLower(img) == target {
			procPostMessageW.Call(hwnd, wmClose, 0, 0)
		}
		return 1
	})
	r1, _, err := procEnumWindows.Call(cb, 0)
	if r1 == 0 {
		return err
	}
	return nil
}

// processImageName returns the base executable name for pid using
// QueryFullProcessImageName, which needs only PROCESS_QUERY_LIMITED_INFORMATION
// (least privilege, works for most processes without elevation).
func processImageName(pid uint32) (string, bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", false
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", false
	}
	return filepath.Base(windows.UTF16ToString(buf[:size])), true
}

func clampPercent(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
