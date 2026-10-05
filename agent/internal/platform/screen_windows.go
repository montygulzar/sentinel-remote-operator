//go:build windows

package platform

import (
	"fmt"
	"image"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Screen capture on Windows uses the documented GDI BitBlt path:
// EnumDisplayMonitors to enumerate displays, then GetDC/CreateCompatibleDC/
// BitBlt/GetDIBits to copy one monitor's pixels into memory. This is a normal,
// supported capture mechanism — not a graphics hook and not a secure-desktop
// grab. Protected or DRM-restricted surfaces come back blank because the OS
// enforces that boundary; Sentinel does not attempt to defeat it (THIRD
// ARTILLERY ORDER, spec §11). Nothing here writes to disk: the frame lives only
// in the returned image.
//
// These procedures reuse moduser32/modkernel32 declared in provider_windows.go
// and add gdi32.
var (
	modgdi32 = windows.NewLazySystemDLL("gdi32.dll")

	procGetDC               = moduser32.NewProc("GetDC")
	procReleaseDC           = moduser32.NewProc("ReleaseDC")
	procEnumDisplayMonitors = moduser32.NewProc("EnumDisplayMonitors")
	procGetMonitorInfoW     = moduser32.NewProc("GetMonitorInfoW")
	procCreateCompatibleDC  = modgdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBmp = modgdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject        = modgdi32.NewProc("SelectObject")
	procBitBlt              = modgdi32.NewProc("BitBlt")
	procGetDIBits           = modgdi32.NewProc("GetDIBits")
	procDeleteObject        = modgdi32.NewProc("DeleteObject")
	procDeleteDC            = modgdi32.NewProc("DeleteDC")
)

type rect struct {
	left, top, right, bottom int32
}

type monitorInfoEx struct {
	cbSize    uint32
	rcMonitor rect
	rcWork    rect
	dwFlags   uint32
	szDevice  [32]uint16
}

type bitmapInfoHeader struct {
	biSize          uint32
	biWidth         int32
	biHeight        int32
	biPlanes        uint16
	biBitCount      uint16
	biCompression   uint32
	biSizeImage     uint32
	biXPelsPerMeter int32
	biYPelsPerMeter int32
	biClrUsed       uint32
	biClrImportant  uint32
}

const (
	monitorPrimaryFlag = 0x00000001
	srcCopy            = 0x00CC0020
	captureBlt         = 0x40000000 // include layered (e.g. alpha-blended) windows
	biRGB              = 0
	dibRGBColors       = 0
)

// winMonitor is an enumerated display with the pixel rectangle needed to
// capture it from the virtual-screen DC.
type winMonitor struct {
	info DisplayInfo
	rc   rect
}

// enumMonitors returns every connected display. EnumDisplayMonitors invokes the
// callback once per monitor on this goroutine (synchronously), so collecting
// into a closure-captured slice is safe without extra synchronisation.
func (p *winProvider) enumMonitors() ([]winMonitor, error) {
	var mons []winMonitor
	var cbErr error
	cb := windows.NewCallback(func(hMonitor, hdc, lprc, lparam uintptr) uintptr {
		var mi monitorInfoEx
		mi.cbSize = uint32(unsafe.Sizeof(mi))
		if r, _, _ := procGetMonitorInfoW.Call(hMonitor, uintptr(unsafe.Pointer(&mi))); r == 0 {
			cbErr = fmt.Errorf("GetMonitorInfoW failed")
			return 1 // keep enumerating; report after
		}
		device := windows.UTF16ToString(mi.szDevice[:])
		primary := mi.dwFlags&monitorPrimaryFlag != 0
		mons = append(mons, winMonitor{
			info: DisplayInfo{
				ID:      device,
				Label:   displayLabel(device, primary, len(mons)),
				Primary: primary,
				Width:   int(mi.rcMonitor.right - mi.rcMonitor.left),
				Height:  int(mi.rcMonitor.bottom - mi.rcMonitor.top),
			},
			rc: mi.rcMonitor,
		})
		return 1 // continue
	})

	r, _, err := procEnumDisplayMonitors.Call(0, 0, cb, 0)
	if r == 0 {
		return nil, fmt.Errorf("EnumDisplayMonitors: %w", err)
	}
	if cbErr != nil {
		return nil, cbErr
	}
	if len(mons) == 0 {
		return nil, ErrUnavailable
	}
	return mons, nil
}

func displayLabel(device string, primary bool, index int) string {
	if primary {
		return "Primary"
	}
	if device != "" {
		return device
	}
	return fmt.Sprintf("Display %d", index+1)
}

func (p *winProvider) Displays() ([]DisplayInfo, error) {
	mons, err := p.enumMonitors()
	if err != nil {
		return nil, err
	}
	out := make([]DisplayInfo, len(mons))
	for i, m := range mons {
		out[i] = m.info
	}
	return out, nil
}

func (p *winProvider) CaptureFrame(displayID string) (Frame, error) {
	mons, err := p.enumMonitors()
	if err != nil {
		return Frame{}, err
	}
	infos := make([]DisplayInfo, len(mons))
	byID := make(map[string]winMonitor, len(mons))
	for i, m := range mons {
		infos[i] = m.info
		byID[m.info.ID] = m
	}
	chosen, ok := resolveDisplay(infos, displayID)
	if !ok {
		return Frame{}, ErrNoSuchDisplay
	}
	mon := byID[chosen.ID]

	start := time.Now()
	img, err := captureRect(mon.rc)
	if err != nil {
		return Frame{}, err
	}
	return Frame{
		DisplayID:  chosen.ID,
		Width:      chosen.Width,
		Height:     chosen.Height,
		Image:      img,
		CapturedAt: start,
		CaptureMs:  time.Since(start).Milliseconds(),
	}, nil
}

// captureRect copies the given virtual-screen rectangle into an *image.RGBA via
// GDI. Every GDI object is released on the way out, success or failure, so a
// repeated Grab Screen leaks no device contexts or bitmaps.
func captureRect(rc rect) (*image.RGBA, error) {
	w := int(rc.right - rc.left)
	h := int(rc.bottom - rc.top)
	if w <= 0 || h <= 0 {
		return nil, fmt.Errorf("display has non-positive size %dx%d", w, h)
	}

	screenDC, _, _ := procGetDC.Call(0)
	if screenDC == 0 {
		return nil, fmt.Errorf("GetDC(screen) failed")
	}
	defer procReleaseDC.Call(0, screenDC)

	memDC, _, _ := procCreateCompatibleDC.Call(screenDC)
	if memDC == 0 {
		return nil, fmt.Errorf("CreateCompatibleDC failed")
	}
	defer procDeleteDC.Call(memDC)

	bitmap, _, _ := procCreateCompatibleBmp.Call(screenDC, uintptr(w), uintptr(h))
	if bitmap == 0 {
		return nil, fmt.Errorf("CreateCompatibleBitmap failed")
	}
	defer procDeleteObject.Call(bitmap)

	prev, _, _ := procSelectObject.Call(memDC, bitmap)
	r, _, _ := procBitBlt.Call(memDC, 0, 0, uintptr(w), uintptr(h),
		screenDC, uintptr(rc.left), uintptr(rc.top), srcCopy|captureBlt)
	procSelectObject.Call(memDC, prev)
	if r == 0 {
		return nil, fmt.Errorf("BitBlt failed (the surface may be protected)")
	}

	// Request a top-down 32-bit BI_RGB DIB so rows are in natural order and
	// each pixel is B,G,R,reserved in memory.
	bih := bitmapInfoHeader{
		biSize:        uint32(unsafe.Sizeof(bitmapInfoHeader{})),
		biWidth:       int32(w),
		biHeight:      int32(-h),
		biPlanes:      1,
		biBitCount:    32,
		biCompression: biRGB,
	}
	buf := make([]byte, w*h*4)
	got, _, _ := procGetDIBits.Call(memDC, bitmap, 0, uintptr(h),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&bih)), dibRGBColors)
	if got == 0 {
		return nil, fmt.Errorf("GetDIBits failed")
	}

	// Convert BGRA (GDI) to RGBA (Go image), forcing opaque alpha: GDI leaves
	// the reserved byte zero, which would otherwise render fully transparent.
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i+3 < len(buf); i += 4 {
		img.Pix[i+0] = buf[i+2] // R
		img.Pix[i+1] = buf[i+1] // G
		img.Pix[i+2] = buf[i+0] // B
		img.Pix[i+3] = 0xff     // A
	}
	return img, nil
}
