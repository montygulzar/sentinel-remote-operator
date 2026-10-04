// Package audit implements Sentinel's append-only audit log (spec §12). Events
// are written to a human-readable daily file and mirrored into a bounded
// in-memory ring so the Operator can read the same stream over the API without
// re-reading disk.
//
// The log records what happened, never the contents of what was captured: the
// caller must not pass screen/camera data, credentials, tokens or command
// output into a message. This package writes exactly the strings it is given.
package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Class categorises an audit event (spec §12 suggested classes).
type Class string

const (
	ClassInfo     Class = "INFO"
	ClassLink     Class = "LINK"
	ClassCommand  Class = "COMMAND"
	ClassScreen   Class = "SCREEN"
	ClassSession  Class = "SESSION"
	ClassSecurity Class = "SECURITY"
	ClassAlert    Class = "ALERT"
	ClassAction   Class = "ACTION"
	ClassSuccess  Class = "SUCCESS"
	ClassError    Class = "ERROR"
)

// Event is a single recorded audit entry.
type Event struct {
	Time    time.Time `json:"time"`
	Class   Class     `json:"class"`
	Message string    `json:"message"`
}

// Line renders the event in the on-disk log format, e.g.
// "[18:42:01] INFO      Sentinel Agent started".
func (e Event) Line() string {
	return fmt.Sprintf("[%s] %-9s %s", e.Time.Format("15:04:05"), string(e.Class), e.Message)
}

const defaultRingSize = 500

// Logger is a concurrency-safe audit logger with daily file rotation and a
// bounded in-memory ring buffer.
type Logger struct {
	dir           string
	retentionDays int
	now           func() time.Time // injectable clock for tests

	mu       sync.Mutex
	file     *os.File
	fileDay  string // YYYY-MM-DD of the currently open file
	ring     []Event
	ringSize int
}

// New creates a Logger writing daily files under dir. retentionDays>0 enables
// deletion of day-files older than that many days on each rotation. The
// directory is created if missing.
func New(dir string, retentionDays int) (*Logger, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	l := &Logger{
		dir:           dir,
		retentionDays: retentionDays,
		now:           time.Now,
		ringSize:      defaultRingSize,
	}
	return l, nil
}

// Log records an event. Formatting follows fmt.Sprintf semantics. Write errors
// are not surfaced to the caller (an action must not fail because logging
// failed); the in-memory ring is always updated so the Operator still sees the
// event.
func (l *Logger) Log(class Class, format string, args ...any) Event {
	ev := Event{Time: l.now(), Class: class, Message: fmt.Sprintf(format, args...)}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.ring = append(l.ring, ev)
	if len(l.ring) > l.ringSize {
		l.ring = l.ring[len(l.ring)-l.ringSize:]
	}

	if err := l.ensureFileLocked(ev.Time); err == nil {
		fmt.Fprintln(l.file, ev.Line())
	}
	return ev
}

// Recent returns up to limit most-recent events (newest last). If classes are
// given, only events in those classes are returned. limit<=0 returns all held
// events.
func (l *Logger) Recent(limit int, classes ...Class) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()

	var want map[Class]bool
	if len(classes) > 0 {
		want = make(map[Class]bool, len(classes))
		for _, c := range classes {
			want[c] = true
		}
	}

	out := make([]Event, 0, len(l.ring))
	for _, ev := range l.ring {
		if want == nil || want[ev.Class] {
			out = append(out, ev)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// Close closes the open day-file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		l.fileDay = ""
		return err
	}
	return nil
}

// ensureFileLocked opens or rotates the day-file so that it matches t's date.
// Caller must hold l.mu.
func (l *Logger) ensureFileLocked(t time.Time) error {
	day := t.Format("2006-01-02")
	if l.file != nil && l.fileDay == day {
		return nil
	}
	if l.file != nil {
		l.file.Close()
		l.file = nil
	}
	path := filepath.Join(l.dir, "sentinel-"+day+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	l.file = f
	l.fileDay = day
	l.pruneLocked(t)
	return nil
}

// pruneLocked deletes day-files older than the retention window. Caller must
// hold l.mu. Failures are ignored; retention is best-effort housekeeping.
func (l *Logger) pruneLocked(now time.Time) {
	if l.retentionDays <= 0 {
		return
	}
	cutoff := now.AddDate(0, 0, -l.retentionDays)
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "sentinel-") || !strings.HasSuffix(name, ".log") {
			continue
		}
		dayStr := strings.TrimSuffix(strings.TrimPrefix(name, "sentinel-"), ".log")
		day, err := time.ParseInLocation("2006-01-02", dayStr, now.Location())
		if err != nil {
			continue
		}
		if day.Before(cutoff) {
			os.Remove(filepath.Join(l.dir, name))
		}
	}
}

// files returns the sorted list of day-file names, used by diagnostics/tests.
func (l *Logger) files() ([]string, error) {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "sentinel-") && strings.HasSuffix(e.Name(), ".log") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}
