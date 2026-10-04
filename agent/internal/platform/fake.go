package platform

import (
	"fmt"
	"image"
	"image/color"
	"time"
)

// Fake is an in-memory Provider for tests. It records the actions invoked on it
// and lets a test inject return values and failures, so the agent's host-facing
// behaviour (PANIC sequencing, control handlers) can be verified without a real
// operating system. It is intentionally simple and lives outside _test.go so
// that tests in other packages can use it.
type Fake struct {
	Name        string
	Info        SystemInfo
	Act         Activity
	SystemErr   error
	ActivityErr error

	// Per-action errors to inject.
	LockErr   error
	VolumeErr error
	MuteErr   error
	CloseErr  error           // fails every CloseApp call
	FailApps  map[string]bool // fails CloseApp only for these image names

	// Screen capture. FakeDisplays, if set, is returned by Displays and used to
	// resolve a requested display id; when nil a single primary display is
	// assumed. CaptureErr, if set, is returned by CaptureFrame to exercise
	// honest capture-error propagation.
	FakeDisplays []DisplayInfo
	CaptureErr   error
	DisplaysErr  error
	CaptureMs    int64

	// Captures records every CaptureFrame call's resolved display id, in order,
	// so tests can assert default/selection behaviour.
	Captures []string

	// Recorded calls, in order.
	Locks         int
	Volumes       []int
	Mutes         []bool
	ClosedApps    []string // apps that closed successfully
	CloseAttempts []string // every app CloseApp was called for, success or not
}

func (f *Fake) DeviceName() string { return f.Name }

func (f *Fake) System() (SystemInfo, error) {
	if f.SystemErr != nil {
		return SystemInfo{}, f.SystemErr
	}
	return f.Info, nil
}

func (f *Fake) Activity() (Activity, error) {
	if f.ActivityErr != nil {
		return Activity{}, f.ActivityErr
	}
	return f.Act, nil
}

func (f *Fake) Lock() error {
	f.Locks++
	return f.LockErr
}

func (f *Fake) SetVolume(percent int) error {
	f.Volumes = append(f.Volumes, percent)
	return f.VolumeErr
}

func (f *Fake) SetMuted(muted bool) error {
	f.Mutes = append(f.Mutes, muted)
	return f.MuteErr
}

func (f *Fake) CloseApp(name string) error {
	f.CloseAttempts = append(f.CloseAttempts, name)
	if f.CloseErr != nil {
		return f.CloseErr
	}
	if f.FailApps[name] {
		return fmt.Errorf("cannot close %s", name)
	}
	f.ClosedApps = append(f.ClosedApps, name)
	return nil
}

// displays returns the configured displays, defaulting to a single primary
// display when none are set.
func (f *Fake) displays() []DisplayInfo {
	if len(f.FakeDisplays) > 0 {
		return f.FakeDisplays
	}
	return []DisplayInfo{{ID: "primary", Label: "Primary", Primary: true, Width: 320, Height: 200}}
}

func (f *Fake) Displays() ([]DisplayInfo, error) {
	if f.DisplaysErr != nil {
		return nil, f.DisplaysErr
	}
	return f.displays(), nil
}

// CaptureFrame returns a synthetic in-memory frame for the resolved display. It
// never touches the filesystem, so tests that assert "no screenshot artifact"
// exercise the real agent flow. An empty id selects the primary display; an
// unknown id returns ErrNoSuchDisplay.
func (f *Fake) CaptureFrame(id string) (Frame, error) {
	if f.CaptureErr != nil {
		f.Captures = append(f.Captures, id)
		return Frame{}, f.CaptureErr
	}
	disp, ok := resolveDisplay(f.displays(), id)
	if !ok {
		return Frame{}, ErrNoSuchDisplay
	}
	f.Captures = append(f.Captures, disp.ID)

	img := image.NewRGBA(image.Rect(0, 0, disp.Width, disp.Height))
	// A simple deterministic gradient: real pixels, not noise, so an encode
	// round-trip in tests has stable, verifiable content.
	for y := 0; y < disp.Height; y++ {
		for x := 0; x < disp.Width; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x), G: uint8(y), B: 0x40, A: 0xff})
		}
	}
	return Frame{
		DisplayID:  disp.ID,
		Width:      disp.Width,
		Height:     disp.Height,
		Image:      img,
		CapturedAt: time.Unix(0, 0).UTC(),
		CaptureMs:  f.CaptureMs,
	}, nil
}
