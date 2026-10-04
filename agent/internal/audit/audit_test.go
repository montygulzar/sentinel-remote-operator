package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogWritesFileAndRing(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()
	l.now = func() time.Time { return time.Date(2026, 1, 2, 18, 42, 1, 0, time.UTC) }

	l.Log(ClassInfo, "Sentinel Agent started")
	l.Log(ClassCommand, "System volume changed")

	// Ring holds both events.
	events := l.Recent(0)
	if len(events) != 2 {
		t.Fatalf("ring has %d events, want 2", len(events))
	}
	if events[0].Class != ClassInfo || events[1].Class != ClassCommand {
		t.Fatalf("unexpected ring contents: %+v", events)
	}

	// File is named by date and contains the formatted lines.
	data, err := os.ReadFile(filepath.Join(dir, "sentinel-2026-01-02.log"))
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	got := string(data)
	wantLine := "[18:42:01] INFO      Sentinel Agent started"
	if !strings.Contains(got, wantLine) {
		t.Fatalf("log file missing line %q; got:\n%s", wantLine, got)
	}
}

func TestLineFormat(t *testing.T) {
	ev := Event{Time: time.Date(2026, 1, 2, 18, 47, 9, 0, time.UTC), Class: ClassSuccess, Message: "PANIC completed // 1.14s"}
	want := "[18:47:09] SUCCESS   PANIC completed // 1.14s"
	if got := ev.Line(); got != want {
		t.Fatalf("Line() = %q, want %q", got, want)
	}
}

func TestRecentFiltersByClassAndLimit(t *testing.T) {
	l, _ := New(t.TempDir(), 0)
	defer l.Close()

	l.Log(ClassInfo, "a")
	l.Log(ClassError, "b")
	l.Log(ClassInfo, "c")
	l.Log(ClassError, "d")

	errs := l.Recent(0, ClassError)
	if len(errs) != 2 || errs[0].Message != "b" || errs[1].Message != "d" {
		t.Fatalf("class filter wrong: %+v", errs)
	}

	last := l.Recent(1)
	if len(last) != 1 || last[0].Message != "d" {
		t.Fatalf("limit wrong: %+v", last)
	}
}

func TestRingIsBounded(t *testing.T) {
	l, _ := New(t.TempDir(), 0)
	defer l.Close()
	l.ringSize = 3

	for _, m := range []string{"1", "2", "3", "4", "5"} {
		l.Log(ClassInfo, "%s", m)
	}
	events := l.Recent(0)
	if len(events) != 3 {
		t.Fatalf("ring size not enforced: %d", len(events))
	}
	if events[0].Message != "3" || events[2].Message != "5" {
		t.Fatalf("ring kept wrong window: %+v", events)
	}
}

func TestDailyRotationAndRetention(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir, 2) // keep 2 days
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	day1 := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return day1 }
	l.Log(ClassInfo, "day one")

	// Jump four days forward; writing should rotate to a new file and prune the
	// first day (older than the 2-day window).
	day5 := day1.AddDate(0, 0, 4)
	l.now = func() time.Time { return day5 }
	l.Log(ClassInfo, "day five")

	files, err := l.files()
	if err != nil {
		t.Fatalf("files: %v", err)
	}
	if len(files) != 1 || files[0] != "sentinel-2026-01-05.log" {
		t.Fatalf("retention did not prune old day-file: %v", files)
	}
}
