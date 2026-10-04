package control

import (
	"errors"
	"testing"

	"github.com/montygulzar/sentinel-remote-operator/agent/internal/audit"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/platform"
)

func newLog(t *testing.T) *audit.Logger {
	t.Helper()
	l, err := audit.New(t.TempDir(), 0)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func TestPanicHappyPathOrderAndResult(t *testing.T) {
	fake := &platform.Fake{}
	svc := NewPanicService(fake, newLog(t), []string{"game.exe", "browser.exe"})

	res := svc.Execute()

	if !res.OK {
		t.Fatalf("expected ok, got %+v", res)
	}
	wantNames := []string{"closeConfiguredApps", "mute", "lock"}
	if len(res.Actions) != 3 {
		t.Fatalf("want 3 actions, got %+v", res.Actions)
	}
	for i, name := range wantNames {
		if res.Actions[i].Name != name || !res.Actions[i].OK {
			t.Fatalf("action %d = %+v, want %s ok", i, res.Actions[i], name)
		}
	}
	// Behaviour actually happened, in the right way.
	if got := fake.ClosedApps; len(got) != 2 || got[0] != "game.exe" || got[1] != "browser.exe" {
		t.Fatalf("closed apps = %v", got)
	}
	if len(fake.Volumes) != 1 || fake.Volumes[0] != 0 {
		t.Fatalf("volume not set to 0: %v", fake.Volumes)
	}
	if fake.Locks != 1 {
		t.Fatalf("lock count = %d, want 1", fake.Locks)
	}
	if res.ElapsedMs < 0 {
		t.Fatalf("elapsed negative: %d", res.ElapsedMs)
	}
}

func TestPanicContinuesAfterFailure(t *testing.T) {
	// Closing apps fails, but PANIC must still mute and lock to secure the box.
	fake := &platform.Fake{CloseErr: errors.New("access denied")}
	svc := NewPanicService(fake, newLog(t), []string{"locked.exe"})

	res := svc.Execute()

	if res.OK {
		t.Fatalf("expected overall failure, got ok")
	}
	if res.Actions[0].OK || res.Actions[0].Error == "" {
		t.Fatalf("close step should have failed with error: %+v", res.Actions[0])
	}
	if !res.Actions[1].OK || !res.Actions[2].OK {
		t.Fatalf("mute and lock should still succeed: %+v", res.Actions)
	}
	if len(fake.Volumes) != 1 || fake.Locks != 1 {
		t.Fatalf("secure steps not attempted after earlier failure: volumes=%v locks=%d", fake.Volumes, fake.Locks)
	}
}

func TestPanicLockFailureReportedButSequenceComplete(t *testing.T) {
	fake := &platform.Fake{LockErr: errors.New("lock unavailable")}
	svc := NewPanicService(fake, newLog(t), nil)

	res := svc.Execute()

	if res.OK {
		t.Fatalf("expected failure when lock fails")
	}
	// close (no apps) and mute succeed; lock fails and is reported truthfully.
	if !res.Actions[0].OK || !res.Actions[1].OK {
		t.Fatalf("early steps should succeed: %+v", res.Actions)
	}
	if res.Actions[2].OK || res.Actions[2].Error == "" {
		t.Fatalf("lock step should report failure: %+v", res.Actions[2])
	}
}

func TestPanicNoConfiguredAppsSucceeds(t *testing.T) {
	fake := &platform.Fake{}
	svc := NewPanicService(fake, newLog(t), nil)

	res := svc.Execute()
	if !res.OK {
		t.Fatalf("empty app list should still secure successfully: %+v", res)
	}
	if len(fake.ClosedApps) != 0 {
		t.Fatalf("no apps should have been closed: %v", fake.ClosedApps)
	}
}

func TestPanicAttemptsEveryAppDespiteFailures(t *testing.T) {
	// The middle app fails to close; the others must still be attempted, and
	// PANIC must still proceed to mute and lock.
	fake := &platform.Fake{FailApps: map[string]bool{"stubborn.exe": true}}
	svc := NewPanicService(fake, newLog(t), []string{"a.exe", "stubborn.exe", "b.exe"})

	res := svc.Execute()

	// Every configured app was attempted, in order.
	want := []string{"a.exe", "stubborn.exe", "b.exe"}
	if len(fake.CloseAttempts) != 3 {
		t.Fatalf("attempts = %v, want all three", fake.CloseAttempts)
	}
	for i, name := range want {
		if fake.CloseAttempts[i] != name {
			t.Fatalf("attempt %d = %q, want %q", i, fake.CloseAttempts[i], name)
		}
	}

	// The close step reports partial failure with per-app detail.
	closeStep := res.Actions[0]
	if closeStep.Name != "closeConfiguredApps" || closeStep.OK {
		t.Fatalf("close step should be partial failure: %+v", closeStep)
	}
	if len(closeStep.Steps) != 3 {
		t.Fatalf("want 3 per-app results, got %+v", closeStep.Steps)
	}
	if closeStep.Steps[0].OK != true || closeStep.Steps[1].OK != false || closeStep.Steps[2].OK != true {
		t.Fatalf("per-app results wrong: %+v", closeStep.Steps)
	}

	// PANIC still muted and locked after the app-close failure.
	if len(fake.Volumes) != 1 || fake.Volumes[0] != 0 {
		t.Fatalf("volume not zeroed after close failure: %v", fake.Volumes)
	}
	if fake.Locks != 1 {
		t.Fatalf("workstation not locked after close failure: %d", fake.Locks)
	}
	if res.OK {
		t.Fatalf("overall result should be partial failure")
	}
}
