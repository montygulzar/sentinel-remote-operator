//go:build !windows

package platform

import "os"

// stub is the Provider used when the agent is built for a non-Windows host.
// Sentinel is a Windows product; this exists so the agent compiles and the API
// can be exercised during development on Linux/macOS. It never fabricates host
// data: metrics are reported unavailable and host actions return
// ErrUnavailable.
type stub struct{ deviceName string }

// New returns the host Provider for the current build target. On non-Windows
// builds it is the honest stub.
func New(deviceName string) Provider {
	if deviceName == "" {
		if h, err := os.Hostname(); err == nil {
			deviceName = h
		} else {
			deviceName = "UNKNOWN"
		}
	}
	return &stub{deviceName: deviceName}
}

func (s *stub) DeviceName() string { return s.deviceName }

func (s *stub) System() (SystemInfo, error) {
	return SystemInfo{DeviceName: s.deviceName, Session: SessionUnknown}, nil
}

func (s *stub) Activity() (Activity, error) {
	return Activity{Session: SessionUnknown}, nil
}

func (s *stub) Lock() error                 { return ErrUnavailable }
func (s *stub) SetVolume(percent int) error { return ErrUnavailable }
func (s *stub) SetMuted(muted bool) error   { return ErrUnavailable }
func (s *stub) CloseApp(name string) error  { return ErrUnavailable }

func (s *stub) Displays() ([]DisplayInfo, error)      { return nil, ErrUnavailable }
func (s *stub) CaptureFrame(id string) (Frame, error) { return Frame{}, ErrUnavailable }
