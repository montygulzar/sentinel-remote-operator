package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/montygulzar/sentinel-remote-operator/agent/internal/audit"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/auth"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/control"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/platform"
)

type harness struct {
	srv   *httptest.Server
	cred  auth.Credential
	fake  *platform.Fake
	log   *audit.Logger
	nonce int
}

func newHarness(t *testing.T, fake *platform.Fake) *harness {
	t.Helper()
	log, err := audit.New(t.TempDir(), 0)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	t.Cleanup(func() { log.Close() })

	cred, _ := auth.GenerateCredential()
	verifier := auth.NewVerifier(cred, 30*time.Second)
	panicSvc := control.NewPanicService(fake, log, nil)
	handler := New(fake, log, verifier, panicSvc).Handler()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &harness{srv: srv, cred: cred, fake: fake, log: log}
}

// do signs and sends a request. If sign is false the auth headers are omitted.
func (h *harness) do(t *testing.T, method, path, body string, sign bool) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, h.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if sign {
		h.nonce++
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		nonce := "n" + strconv.Itoa(h.nonce)
		sig := auth.Signature(h.cred.Key, auth.SignedRequest{
			DeviceID:  h.cred.DeviceID,
			Method:    method,
			Path:      path,
			Timestamp: ts,
			Nonce:     nonce,
			Body:      []byte(body),
		})
		req.Header.Set(auth.HeaderDevice, h.cred.DeviceID)
		req.Header.Set(auth.HeaderTimestamp, ts)
		req.Header.Set(auth.HeaderNonce, nonce)
		req.Header.Set(auth.HeaderSignature, sig)
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func decode[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var v T
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("decode body %q: %v", string(data), err)
	}
	return v
}

func TestUnauthenticatedRequestRejected(t *testing.T) {
	h := newHarness(t, &platform.Fake{})
	resp := h.do(t, "GET", "/v1/status", "", false)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
	if h.fake.Locks != 0 {
		t.Fatalf("no action should have run for an unauthenticated request")
	}
}

func TestStatusReturnsRealValuesAndNullsUnavailable(t *testing.T) {
	cpu := 16
	idle := int64(42)
	fake := &platform.Fake{Info: platform.SystemInfo{
		DeviceName:  "BEEFCAKES",
		Session:     platform.SessionUnlocked,
		CPUPercent:  &cpu,
		IdleSeconds: &idle,
		// RAM, battery, uptime deliberately left nil (unavailable).
	}}
	h := newHarness(t, fake)

	resp := h.do(t, "GET", "/v1/status", "", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := decode[map[string]any](t, resp)

	if body["deviceName"] != "BEEFCAKES" || body["online"] != true || body["session"] != "unlocked" {
		t.Fatalf("unexpected status body: %v", body)
	}
	if body["cpuPercent"].(float64) != 16 {
		t.Fatalf("cpuPercent = %v, want 16", body["cpuPercent"])
	}
	// Unavailable metrics must be JSON null, not a fabricated zero.
	for _, k := range []string{"ramPercent", "batteryPercent", "uptimeSeconds"} {
		if v, ok := body[k]; !ok || v != nil {
			t.Fatalf("%s = %v, want null", k, v)
		}
	}
}

func TestLockActionRunsAndIsAudited(t *testing.T) {
	h := newHarness(t, &platform.Fake{})
	resp := h.do(t, "POST", "/v1/control/lock", "", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := decode[map[string]any](t, resp)
	if body["ok"] != true {
		t.Fatalf("lock not ok: %v", body)
	}
	if h.fake.Locks != 1 {
		t.Fatalf("lock not invoked")
	}
	// Spec §17: every control action creates an audit event.
	if len(h.log.Recent(0, audit.ClassAction)) == 0 {
		t.Fatalf("no ACTION audit event recorded for lock")
	}
}

func TestMuteDefaultsToMuted(t *testing.T) {
	h := newHarness(t, &platform.Fake{})
	resp := h.do(t, "POST", "/v1/control/mute", "", true)
	resp.Body.Close()
	if len(h.fake.Mutes) != 1 || h.fake.Mutes[0] != true {
		t.Fatalf("mute default wrong: %v", h.fake.Mutes)
	}

	resp = h.do(t, "POST", "/v1/control/mute", `{"muted":false}`, true)
	resp.Body.Close()
	if len(h.fake.Mutes) != 2 || h.fake.Mutes[1] != false {
		t.Fatalf("explicit unmute wrong: %v", h.fake.Mutes)
	}
}

func TestPanicEndpointReturnsStructuredResult(t *testing.T) {
	h := newHarness(t, &platform.Fake{})
	resp := h.do(t, "POST", "/v1/control/panic", "", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	res := decode[control.Result](t, resp)
	if !res.OK || len(res.Actions) != 3 {
		t.Fatalf("unexpected panic result: %+v", res)
	}
	if h.fake.Locks != 1 || len(h.fake.Volumes) != 1 || h.fake.Volumes[0] != 0 {
		t.Fatalf("panic did not secure the host: %+v", h.fake)
	}
}

func TestLogsWithSignedQueryFilter(t *testing.T) {
	h := newHarness(t, &platform.Fake{})
	// Generate a couple of auditable actions first.
	h.do(t, "POST", "/v1/control/lock", "", true).Body.Close()

	// A query string must be covered by the signature and still verify.
	resp := h.do(t, "GET", "/v1/logs?limit=5&class=ACTION", "", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logs with query = %d, want 200", resp.StatusCode)
	}
	body := decode[struct {
		Events []audit.Event `json:"events"`
	}](t, resp)
	for _, e := range body.Events {
		if e.Class != audit.ClassAction {
			t.Fatalf("class filter leaked %s", e.Class)
		}
	}
}

func TestWrongMethodIsRejected(t *testing.T) {
	h := newHarness(t, &platform.Fake{})
	// /v1/status exists only for GET; a POST must be 405, not 404.
	resp := h.do(t, "POST", "/v1/status", "", true)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

func TestReplayRejectedEndToEnd(t *testing.T) {
	h := newHarness(t, &platform.Fake{})
	// Build one signed request and send its exact bytes twice.
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "replay-1"
	sig := auth.Signature(h.cred.Key, auth.SignedRequest{
		DeviceID: h.cred.DeviceID, Method: "POST", Path: "/v1/control/lock",
		Timestamp: ts, Nonce: nonce, Body: nil,
	})
	send := func() int {
		req, _ := http.NewRequest("POST", h.srv.URL+"/v1/control/lock", nil)
		req.Header.Set(auth.HeaderDevice, h.cred.DeviceID)
		req.Header.Set(auth.HeaderTimestamp, ts)
		req.Header.Set(auth.HeaderNonce, nonce)
		req.Header.Set(auth.HeaderSignature, sig)
		resp, err := h.srv.Client().Do(req)
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := send(); code != http.StatusOK {
		t.Fatalf("first send = %d, want 200", code)
	}
	if code := send(); code != http.StatusUnauthorized {
		t.Fatalf("replayed send = %d, want 401", code)
	}
}
