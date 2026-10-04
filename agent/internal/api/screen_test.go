package api

import (
	"bytes"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/montygulzar/sentinel-remote-operator/agent/internal/platform"
)

// twoDisplays is a fake with a non-primary extra display, for selection tests.
func twoDisplays() []platform.DisplayInfo {
	return []platform.DisplayInfo{
		{ID: "DISPLAY1", Label: "Primary", Primary: true, Width: 320, Height: 200},
		{ID: "DISPLAY2", Label: "DISPLAY2", Primary: false, Width: 64, Height: 48},
	}
}

func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return data
}

func TestGrabScreenRequiresAuth(t *testing.T) {
	fake := &platform.Fake{}
	h := newHarness(t, fake)

	resp := h.do(t, "GET", "/v1/screen/grab", "", false)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
	if len(fake.Captures) != 0 {
		t.Fatalf("unauthenticated request must not trigger a capture, got %v", fake.Captures)
	}
}

func TestGrabScreenReturnsDecodableJPEGWithMetadata(t *testing.T) {
	fake := &platform.Fake{FakeDisplays: twoDisplays(), CaptureMs: 7}
	h := newHarness(t, fake)

	resp := h.do(t, "GET", "/v1/screen/grab", "", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "image/jpeg" {
		t.Fatalf("content-type = %q, want image/jpeg", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("cache-control = %q, want no-store (frame is ephemeral)", cc)
	}
	data := readBody(t, resp)

	img, err := jpeg.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("returned body is not a decodable JPEG: %v", err)
	}
	if got := img.Bounds().Dx(); got != 320 {
		t.Fatalf("decoded width = %d, want 320", got)
	}
	if got := img.Bounds().Dy(); got != 200 {
		t.Fatalf("decoded height = %d, want 200", got)
	}

	// Metadata headers describe the captured primary display.
	wantHeaders := map[string]string{
		headerCaptureDisplay: "DISPLAY1",
		headerCaptureWidth:   "320",
		headerCaptureHeight:  "200",
		headerCaptureFormat:  "jpeg",
		headerCaptureMs:      "7",
	}
	for k, want := range wantHeaders {
		if got := resp.Header.Get(k); got != want {
			t.Fatalf("header %s = %q, want %q", k, got, want)
		}
	}
	if _, err := strconv.ParseInt(resp.Header.Get(headerCaptureTimestamp), 10, 64); err != nil {
		t.Fatalf("capture timestamp header is not an integer: %q", resp.Header.Get(headerCaptureTimestamp))
	}
	if _, err := strconv.ParseInt(resp.Header.Get(headerEncodeMs), 10, 64); err != nil {
		t.Fatalf("encode-ms header is not an integer: %q", resp.Header.Get(headerEncodeMs))
	}
}

func TestGrabScreenDefaultsToPrimaryDisplay(t *testing.T) {
	fake := &platform.Fake{FakeDisplays: twoDisplays()}
	h := newHarness(t, fake)

	resp := h.do(t, "GET", "/v1/screen/grab", "", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
	if len(fake.Captures) != 1 || fake.Captures[0] != "DISPLAY1" {
		t.Fatalf("captures = %v, want the primary display [DISPLAY1]", fake.Captures)
	}
	if got := resp.Header.Get(headerCaptureDisplay); got != "DISPLAY1" {
		t.Fatalf("captured display header = %q, want DISPLAY1", got)
	}
}

func TestGrabScreenSelectsRequestedDisplay(t *testing.T) {
	fake := &platform.Fake{FakeDisplays: twoDisplays()}
	h := newHarness(t, fake)

	resp := h.do(t, "GET", "/v1/screen/grab?display=DISPLAY2", "", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	data := readBody(t, resp)
	img, err := jpeg.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode jpeg: %v", err)
	}
	if img.Bounds().Dx() != 64 || img.Bounds().Dy() != 48 {
		t.Fatalf("decoded size = %dx%d, want 64x48 (DISPLAY2)", img.Bounds().Dx(), img.Bounds().Dy())
	}
	if len(fake.Captures) != 1 || fake.Captures[0] != "DISPLAY2" {
		t.Fatalf("captures = %v, want [DISPLAY2]", fake.Captures)
	}
}

func TestGrabScreenInvalidDisplayIs404(t *testing.T) {
	fake := &platform.Fake{FakeDisplays: twoDisplays()}
	h := newHarness(t, fake)

	resp := h.do(t, "GET", "/v1/screen/grab?display=NOPE", "", true)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestGrabScreenCaptureErrorIsReportedHonestly(t *testing.T) {
	// A host that cannot capture (e.g. a protected surface, or the headless
	// non-Windows stub) must surface a non-2xx rejection, never a blank 200.
	fake := &platform.Fake{CaptureErr: platform.ErrUnavailable}
	h := newHarness(t, fake)

	resp := h.do(t, "GET", "/v1/screen/grab", "", true)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	body := decode[map[string]any](t, resp)
	if body["ok"] != false {
		t.Fatalf("error body ok = %v, want false", body["ok"])
	}
}

func TestGrabScreenPNGFormat(t *testing.T) {
	fake := &platform.Fake{FakeDisplays: twoDisplays()}
	h := newHarness(t, fake)

	resp := h.do(t, "GET", "/v1/screen/grab?format=png", "", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "image/png" {
		t.Fatalf("content-type = %q, want image/png", ct)
	}
	data := readBody(t, resp)
	if _, err := png.Decode(bytes.NewReader(data)); err != nil {
		t.Fatalf("returned body is not a decodable PNG: %v", err)
	}
}

func TestGrabScreenRejectsBadFormatAndQuality(t *testing.T) {
	fake := &platform.Fake{FakeDisplays: twoDisplays()}
	h := newHarness(t, fake)

	for _, path := range []string{
		"/v1/screen/grab?format=gif",
		"/v1/screen/grab?quality=0",
		"/v1/screen/grab?quality=101",
		"/v1/screen/grab?quality=abc",
	} {
		resp := h.do(t, "GET", path, "", true)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400", path, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

// TestGrabScreenLeavesNoDiskArtifact verifies the capture→memory→encode→
// transmit→discard flow never spills a screenshot to disk (spec §11, THIRD
// ARTILLERY ORDER). It scans the agent's entire writable data tree after
// several grabs and fails if any image-typed file appears.
func TestGrabScreenLeavesNoDiskArtifact(t *testing.T) {
	fake := &platform.Fake{FakeDisplays: twoDisplays()}
	h := newHarness(t, fake)
	root := h.dataRoot

	for i := 0; i < 3; i++ {
		resp := h.do(t, "GET", "/v1/screen/grab", "", true)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("grab %d: status = %d, want 200", i, resp.StatusCode)
		}
		if len(readBody(t, resp)) == 0 {
			t.Fatalf("grab %d returned an empty body", i)
		}
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		var magic [8]byte
		n, _ := io.ReadFull(f, magic[:])
		if looksLikeImage(magic[:n]) {
			t.Fatalf("found image-like artifact on disk: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk data root: %v", err)
	}
}

// looksLikeImage reports whether b starts with the JPEG or PNG magic bytes.
func looksLikeImage(b []byte) bool {
	jpegMagic := []byte{0xFF, 0xD8, 0xFF}
	pngMagic := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	return bytes.HasPrefix(b, jpegMagic) || bytes.HasPrefix(b, pngMagic)
}
