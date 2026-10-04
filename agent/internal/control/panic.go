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

// StepResult is the outcome of one PANIC step. Steps carries per-item results
// for a step that fans out over several targets (the per-application results of
// closeConfiguredApps), so a caller can see exactly which items failed.
type StepResult struct {
	Name  string       `json:"name"`
	OK    bool         `json:"ok"`
	Error string       `json:"error,omitempty"`
	Steps []StepResult `json:"steps,omitempty"`
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

	// Every step is evaluated here, so a failure in one does not prevent the
	// others: PANIC secures as much as possible (spec §7). closeConfiguredApps
	// itself attempts every configured application before returning.
	actions := []StepResult{
		s.closeConfiguredApps(),
		s.step("mute", func() error { return s.provider.SetVolume(0) }),
		s.step("lock", s.provider.Lock),
	}

	ok := true
	for _, a := range actions {
		if !a.OK {
			ok = false
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

// closeConfiguredApps attempts to close every configured application in order,
// continuing past any individual failure so that one stubborn application does
// not leave the rest open (spec §7, Milestone 2 review). Each attempt is
// recorded as a sub-result; the step is OK only if every application closed.
// Closing an app that is not running is not an error (Provider contract).
func (s *PanicService) closeConfiguredApps() StepResult {
	step := StepResult{Name: "closeConfiguredApps", OK: true}
	for _, app := range s.closeApps {
		if err := s.provider.CloseApp(app); err != nil {
			s.log.Log(audit.ClassError, "PANIC close %s failed: %v", app, err)
			step.Steps = append(step.Steps, StepResult{Name: app, OK: false, Error: err.Error()})
			step.OK = false
			continue
		}
		s.log.Log(audit.ClassAction, "PANIC closed %s", app)
		step.Steps = append(step.Steps, StepResult{Name: app, OK: true})
	}
	if !step.OK {
		step.Error = "one or more applications failed to close"
	}
	return step
}
