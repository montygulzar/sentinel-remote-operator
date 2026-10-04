package platform

import "fmt"

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
