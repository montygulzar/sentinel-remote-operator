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

import "errors"

// ErrUnavailable is returned by a Provider when a requested capability is not
// supported on the current host (for example, audio control on a headless
// server). Callers surface this to the Operator as UNAVAILABLE rather than
// pretending the action succeeded.
var ErrUnavailable = errors.New("capability unavailable")

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
}
