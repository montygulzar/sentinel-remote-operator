// Package control implements deliberate host actions (spec §6, §7). The PANIC
// preset is the most safety-critical path in the agent: it must run its whole
// sequence even when a step fails, report the real outcome of each step, and
// never claim success it did not achieve (spec §17).
package control

import (
	"time"

	"github.com/montygulzar/sentinel-remote-operator/agent/internal/audit"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/platform"
)

// StepResult is the outcome of one PANIC step.
type StepResult struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Result is the structured outcome of a PANIC execution (spec §19).
type Result struct {
	OK        bool         `json:"ok"`
	Actions   []StepResult `json:"actions"`
	ElapsedMs int64        `json:"elapsedMs"`
}

// PanicService executes the configured PANIC preset.
type PanicService struct {
	provider  platform.Provider
	log       *audit.Logger
	closeApps []string
	now       func() time.Time
}

// NewPanicService wires the preset. closeApps are executable image names closed
// first, in order.
func NewPanicService(p platform.Provider, log *audit.Logger, closeApps []string) *PanicService {
	return &PanicService{provider: p, log: log, closeApps: closeApps, now: time.Now}
}

// Execute runs the PANIC sequence: close configured applications, set system
// volume to zero, then lock the workstation (spec §7). All steps are attempted
// regardless of earlier failures so that the machine is still secured as far as
// possible. The returned Result.OK is true only if every step succeeded.
func (s *PanicService) Execute() Result {
	start := s.now()
	s.log.Log(audit.ClassCommand, "PANIC received")

	actions := []StepResult{
		s.step("closeConfiguredApps", s.closeConfiguredApps),
		s.step("mute", func() error { return s.provider.SetVolume(0) }),
		s.step("lock", s.provider.Lock),
	}

	ok := true
	for _, a := range actions {
		if !a.OK {
			ok = false
			break
		}
	}

	elapsed := s.now().Sub(start)
	res := Result{OK: ok, Actions: actions, ElapsedMs: elapsed.Milliseconds()}
	if ok {
		s.log.Log(audit.ClassSuccess, "PANIC completed // %.2fs", elapsed.Seconds())
	} else {
		s.log.Log(audit.ClassAlert, "PANIC partial failure // %.2fs", elapsed.Seconds())
	}
	return res
}

// step runs one named action, audits it, and captures its outcome.
func (s *PanicService) step(name string, fn func() error) StepResult {
	if err := fn(); err != nil {
		s.log.Log(audit.ClassError, "PANIC step %s failed: %v", name, err)
		return StepResult{Name: name, OK: false, Error: err.Error()}
	}
	s.log.Log(audit.ClassAction, "PANIC step %s", name)
	return StepResult{Name: name, OK: true}
}

// closeConfiguredApps closes each configured application in order. Closing an
// app that is not running is not an error (that is the Provider's contract), so
// this fails only on a real inability to close one.
func (s *PanicService) closeConfiguredApps() error {
	for _, app := range s.closeApps {
		if err := s.provider.CloseApp(app); err != nil {
			return err
		}
	}
	return nil
}
