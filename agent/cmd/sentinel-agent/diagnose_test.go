package main

import (
	"bytes"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/montygulzar/sentinel-remote-operator/agent/internal/platform"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/screen"
)

func twoDisplays() []platform.DisplayInfo {
	return []platform.DisplayInfo{
		{ID: "DISPLAY1", Label: "Primary", Primary: true, Width: 320, Height: 200},
		{ID: "DISPLAY2", Label: "DISPLAY2", Primary: false, Width: 64, Height: 48},
	}
}

func TestDiagnoseScreenWritesDecodableImage(t *testing.T) {
	fake := &platform.Fake{FakeDisplays: twoDisplays(), CaptureMs: 9}
	out := filepath.Join(t.TempDir(), "diag.jpg")

	rep, err := diagnoseScreen(fake, "", screen.FormatJPEG, 80, out)
	if err != nil {
		t.Fatalf("diagnoseScreen: %v", err)
	}
	if rep.Display != "DISPLAY1" {
		t.Fatalf("display = %q, want the primary DISPLAY1", rep.Display)
	}
	if rep.Width != 320 || rep.Height != 200 {
		t.Fatalf("dimensions = %dx%d, want 320x200", rep.Width, rep.Height)
	}
	if rep.CaptureMs != 9 {
		t.Fatalf("captureMs = %d, want 9", rep.CaptureMs)
	}
	if rep.Bytes <= 0 || rep.OutPath != out {
		t.Fatalf("unexpected report: %+v", rep)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if len(data) != rep.Bytes {
		t.Fatalf("file size %d != reported %d", len(data), rep.Bytes)
	}
	if _, err := jpeg.Decode(bytes.NewReader(data)); err != nil {
		t.Fatalf("output is not a decodable JPEG: %v", err)
	}
}

func TestDiagnoseScreenSelectsDisplay(t *testing.T) {
	fake := &platform.Fake{FakeDisplays: twoDisplays()}
	out := filepath.Join(t.TempDir(), "diag.jpg")

	rep, err := diagnoseScreen(fake, "DISPLAY2", screen.FormatJPEG, 0, out)
	if err != nil {
		t.Fatalf("diagnoseScreen: %v", err)
	}
	if rep.Display != "DISPLAY2" || rep.Width != 64 || rep.Height != 48 {
		t.Fatalf("unexpected report for DISPLAY2: %+v", rep)
	}
}

func TestDiagnoseScreenPNG(t *testing.T) {
	fake := &platform.Fake{FakeDisplays: twoDisplays()}
	out := filepath.Join(t.TempDir(), "diag.png")

	if _, err := diagnoseScreen(fake, "", screen.FormatPNG, 0, out); err != nil {
		t.Fatalf("diagnoseScreen png: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if _, err := png.Decode(bytes.NewReader(data)); err != nil {
		t.Fatalf("output is not a decodable PNG: %v", err)
	}
}

func TestDiagnoseScreenCaptureErrorWritesNoFile(t *testing.T) {
	fake := &platform.Fake{CaptureErr: platform.ErrUnavailable}
	out := filepath.Join(t.TempDir(), "should-not-exist.jpg")

	if _, err := diagnoseScreen(fake, "", screen.FormatJPEG, 80, out); err == nil {
		t.Fatalf("expected an error when capture is unavailable")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("no file should be written on capture failure, but %s exists", out)
	}
}
