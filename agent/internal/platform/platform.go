// Package platform defines the operating-system capabilities the Sentinel
// agent needs. Everything the agent does to the host machine goes through the
// Provider interface so that the agent's real logic — authentication, PANIC
// sequencing, audit logging, status assembly — is testable on any OS, while
// the Windows syscalls live in a build-tagged implementation.
//
// Honesty rule (spec §2): a value that cannot be obtained is reported as
// unavailable (a nil pointer that serialises to JSON null), never estimated or
// invented. Actions that the host cannot perform return ErrUnavailable.
package platform

import (
	"errors"
	"image"
	"time"
)

// ErrUnavailable is returned by a Provider when a requested capability is not
// supported on the current host (for example, audio control on a headless
// server). Callers surface this to the Operator as UNAVAILABLE rather than
// pretending the action succeeded.
var ErrUnavailable = errors.New("capability unavailable")

// ErrNoSuchDisplay is returned by CaptureFrame when the requested display id
// does not match any connected display.
var ErrNoSuchDisplay = errors.New("no such display")

// SessionState is the lock state of the interactive desktop session.
type SessionState string

const (
	SessionUnlocked SessionState = "unlocked"
	SessionLocked   SessionState = "locked"
	// SessionUnknown is used when the host cannot determine lock state. It is
	// reported truthfully rather than guessed.
	SessionUnknown SessionState = "unknown"
)

// SystemInfo is a one-shot snapshot of host health. Optional metrics are
// pointers so that an unavailable metric is null on the wire instead of a
// misleading zero.
type SystemInfo struct {
	DeviceName     string       `json:"deviceName"`
	Session        SessionState `json:"session"`
	IdleSeconds    *int64       `json:"idleSeconds"`
	UptimeSeconds  *int64       `json:"uptimeSeconds"`
	CPUPercent     *int         `json:"cpuPercent"`
	RAMPercent     *int         `json:"ramPercent"`
	BatteryPercent *int         `json:"batteryPercent"`
}

// Activity describes what the local user is doing right now.
type Activity struct {
	Session     SessionState `json:"session"`
	ActiveApp   *string      `json:"activeApp"`
	IdleSeconds *int64       `json:"idleSeconds"`
}

// resolveDisplay selects the display a CaptureFrame call targets. An empty id
// selects the display marked primary (or the first, if none is marked); a
// non-empty id must match a display exactly. It is shared by every Provider
// implementation so the default/selection rule is identical on all of them.
func resolveDisplay(displays []DisplayInfo, id string) (DisplayInfo, bool) {
	if len(displays) == 0 {
		return DisplayInfo{}, false
	}
	if id == "" {
		for _, d := range displays {
			if d.Primary {
				return d, true
			}
		}
		return displays[0], true
	}
	for _, d := range displays {
		if d.ID == id {
			return d, true
		}
	}
	return DisplayInfo{}, false
}

// DisplayInfo describes one connected display. ID is a stable string the
// Operator passes back to CaptureFrame to select a display; Primary marks the
// default display captured when no id is requested. Multi-display support is
// built in from the start so Grab Screen is not a single-display dead end
// (THIRD ARTILLERY ORDER), while display selection beyond the primary default
// is left to a later Operator capability.
type DisplayInfo struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Primary bool   `json:"primary"`
	Width   int    `json:"width"`
	Height  int    `json:"height"`
}

// Frame is a single captured screen frame held entirely in memory (spec §11:
// capture → memory → encode → transmit → discard). The raw pixels live in
// Image; encoding to a wire format is done by the platform-independent screen
// package so it is testable on any OS. CaptureMs records how long the host grab
// itself took, for the performance budget Grab Screen is meant to keep.
type Frame struct {
	DisplayID  string
	Width      int
	Height     int
	Image      image.Image
	CapturedAt time.Time
	CaptureMs  int64
}

// Provider is the full set of host capabilities used by Milestone 1. It is kept
// deliberately narrow (spec §18: keep endpoints and capabilities narrow); later
// milestones extend it behind the same interface rather than widening handlers.
type Provider interface {
	// DeviceName returns the host's configured name. It never fails; if the
	// real name is unknown the implementation returns a stable fallback.
	DeviceName() string

	// System returns a current health snapshot. Fields that cannot be read are
	// left nil; the method only returns an error for a total failure to sample.
	System() (SystemInfo, error)

	// Activity returns current session/idle/foreground-app state.
	Activity() (Activity, error)

	// Lock locks the interactive workstation session.
	Lock() error

	// SetVolume sets the system master output volume to percent (0..100).
	// PANIC uses SetVolume(0); the MUTE control toggles SetMuted.
	SetVolume(percent int) error

	// SetMuted mutes or unmutes the system master output.
	SetMuted(muted bool) error

	// CloseApp requests that the named user application close. The name is an
	// executable image name (for example "chrome.exe"); matching is the
	// implementation's responsibility. Closing an app that is not running is
	// not an error.
	CloseApp(name string) error

	// Displays lists the host's connected displays, with exactly one marked
	// primary when any are present. It returns ErrUnavailable on a host that
	// cannot enumerate displays.
	Displays() ([]DisplayInfo, error)

	// CaptureFrame captures a single frame of the identified display into
	// memory and returns it. An empty displayID selects the primary display.
	// The implementation uses only normal, supported OS capture APIs and never
	// attempts to defeat an OS security boundary: a protected or secure surface
	// that the OS refuses to hand over is reported as an error, not bypassed
	// (THIRD ARTILLERY ORDER, spec §11). An unknown displayID returns
	// ErrNoSuchDisplay; an unsupported host returns ErrUnavailable.
	CaptureFrame(displayID string) (Frame, error)
}
