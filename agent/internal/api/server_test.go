package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	srv      *httptest.Server
	reg      *auth.Registry
	devID    string
	devKey   []byte
	adminKey []byte
	fake     *platform.Fake
	log      *audit.Logger
	nonce    int
}

func newHarness(t *testing.T, fake *platform.Fake) *harness {
	t.Helper()
	log, err := audit.New(t.TempDir(), 0)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	t.Cleanup(func() { log.Close() })

	reg, err := auth.OpenRegistry(filepath.Join(t.TempDir(), "devices.json"), auth.NewProtector())
	if err != nil {
		t.Fatalf("OpenRegistry: %v", err)
	}
	devKey := randomKey(t)
	if err := reg.Add(&auth.Device{ID: "dev-1", DisplayName: "iPhone", Key: devKey, CreatedAt: time.Now(), ProtocolVersion: 1}); err != nil {
		t.Fatalf("Add device: %v", err)
	}
	adminKey := randomKey(t)

	authn := auth.NewAuthenticator(reg, adminKey, 30*time.Second)
	pairing := auth.NewPairingManager(reg, log, 5*time.Minute, 30*time.Second)
	panicSvc := control.NewPanicService(fake, log, nil)
	handler := New(fake, log, authn, pairing, reg, panicSvc, true).Handler()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &harness{srv: srv, reg: reg, devID: "dev-1", devKey: devKey, adminKey: adminKey, fake: fake, log: log}
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// do signs and sends a request as the harness's paired device. If sign is false
// the auth headers are omitted.
func (h *harness) do(t *testing.T, method, path, body string, sign bool) *http.Response {
	t.Helper()
	if !sign {
		return h.send(t, method, path, body, nil)
	}
	return h.sendSigned(t, h.devID, h.devKey, method, path, body)
}

// doAdmin signs and sends a request with the admin key.
func (h *harness) doAdmin(t *testing.T, method, path, body string) *http.Response {
	t.Helper()
	return h.sendSigned(t, "admin", h.adminKey, method, path, body)
}

func (h *harness) sendSigned(t *testing.T, deviceID string, key []byte, method, path, body string) *http.Response {
	t.Helper()
	h.nonce++
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "n" + strconv.Itoa(h.nonce)
	sig := auth.Signature(key, auth.SignedRequest{
		DeviceID: deviceID, Method: method, Path: path,
		Timestamp: ts, Nonce: nonce, Body: []byte(body),
	})
	return h.send(t, method, path, body, map[string]string{
		auth.HeaderDevice:    deviceID,
		auth.HeaderTimestamp: ts,
		auth.HeaderNonce:     nonce,
		auth.HeaderSignature: sig,
	})
}

func (h *harness) send(t *testing.T, method, path, body string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, h.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
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
	sig := auth.Signature(h.devKey, auth.SignedRequest{
		DeviceID: h.devID, Method: "POST", Path: "/v1/control/lock",
		Timestamp: ts, Nonce: nonce, Body: nil,
	})
	send := func() int {
		req, _ := http.NewRequest("POST", h.srv.URL+"/v1/control/lock", nil)
		req.Header.Set(auth.HeaderDevice, h.devID)
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

// --- Milestone 2: pairing, revocation and admin transport over HTTP ---

func TestUnknownDeviceRejected(t *testing.T) {
	h := newHarness(t, &platform.Fake{})
	// Well-formed signed request, but the device id is not registered.
	resp := h.sendSigned(t, "ghost", randomKey(t), "GET", "/v1/status", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown device status = %d, want 401", resp.StatusCode)
	}
}

// pairOverHTTP runs a full pairing exchange and returns the new device's id and
// its independently derived permanent key.
func pairOverHTTP(t *testing.T, h *harness, displayName string) (string, []byte) {
	t.Helper()
	// Owner opens the pairing window via the admin channel.
	startResp := h.doAdmin(t, "POST", "/v1/admin/pairing/start", "")
	if startResp.StatusCode != http.StatusOK {
		t.Fatalf("pairing start = %d, want 200", startResp.StatusCode)
	}
	start := decode[pairingStartResponse](t, startResp)
	if start.Code == "" {
		t.Fatalf("pairing start returned empty code")
	}

	// Operator contributes a nonce and signs the request with the code.
	dn := randomKey(t)[:16]
	dnB64 := base64.StdEncoding.EncodeToString(dn)
	body, _ := json.Marshal(auth.PairRequest{DisplayName: displayName, DeviceNonce: dnB64})
	resp := h.sendSigned(t, "pairing", []byte(start.Code), "POST", "/v1/pair", string(body))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pair = %d, want 200", resp.StatusCode)
	}
	res := decode[auth.PairResult](t, resp)

	key, err := auth.DeriveDeviceKey(start.Code, res.AgentNonce, dnB64)
	if err != nil {
		t.Fatalf("DeriveDeviceKey: %v", err)
	}
	return res.DeviceID, key
}

func TestPairedDeviceCanAuthenticate(t *testing.T) {
	h := newHarness(t, &platform.Fake{})
	id, key := pairOverHTTP(t, h, "New iPhone")

	// The freshly paired device authenticates a normal request.
	resp := h.sendSigned(t, id, key, "GET", "/v1/status", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("paired device status = %d, want 200", resp.StatusCode)
	}

	// DEVICE_PAIRED was audited.
	var paired bool
	for _, e := range h.log.Recent(0, audit.ClassSecurity) {
		if strings.Contains(e.Message, "DEVICE_PAIRED") {
			paired = true
		}
	}
	if !paired {
		t.Fatalf("DEVICE_PAIRED not audited")
	}
}

func TestRevocationIsImmediateOverHTTP(t *testing.T) {
	h := newHarness(t, &platform.Fake{})
	id, key := pairOverHTTP(t, h, "Doomed")

	// Works before revocation.
	if resp := h.sendSigned(t, id, key, "GET", "/v1/status", ""); resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("pre-revoke status = %d, want 200", resp.StatusCode)
	}

	// Revoke via admin.
	revResp := h.doAdmin(t, "POST", "/v1/admin/devices/revoke", `{"deviceId":"`+id+`"}`)
	if revResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke = %d, want 200", revResp.StatusCode)
	}
	rev := decode[map[string]any](t, revResp)
	if rev["revoked"] != true {
		t.Fatalf("revoke result = %v", rev)
	}

	// The next request from that device is immediately rejected.
	resp := h.sendSigned(t, id, key, "GET", "/v1/status", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-revoke status = %d, want 401", resp.StatusCode)
	}

	var revoked bool
	for _, e := range h.log.Recent(0, audit.ClassSecurity) {
		if strings.Contains(e.Message, "DEVICE_REVOKED") {
			revoked = true
		}
	}
	if !revoked {
		t.Fatalf("DEVICE_REVOKED not audited")
	}
}

func TestDeviceListExposesNoSecret(t *testing.T) {
	h := newHarness(t, &platform.Fake{})
	pairOverHTTP(t, h, "Listed")

	resp := h.doAdmin(t, "GET", "/v1/admin/devices", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("devices = %d, want 200", resp.StatusCode)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if strings.Contains(strings.ToLower(string(raw)), "\"key\"") {
		t.Fatalf("device listing exposed a key field: %s", raw)
	}
	// Two devices: the seeded one plus the newly paired one.
	var out struct {
		Devices []auth.Info `json:"devices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Devices) != 2 {
		t.Fatalf("want 2 devices listed, got %d", len(out.Devices))
	}
}

func TestAdminRejectedFromNonLoopback(t *testing.T) {
	log, _ := audit.New(t.TempDir(), 0)
	defer log.Close()
	reg, _ := auth.OpenRegistry(filepath.Join(t.TempDir(), "d.json"), auth.NewProtector())
	authn := auth.NewAuthenticator(reg, randomKey(t), 30*time.Second)
	pairing := auth.NewPairingManager(reg, log, 5*time.Minute, 30*time.Second)
	handler := New(&platform.Fake{}, log, authn, pairing, reg, control.NewPanicService(&platform.Fake{}, log, nil), true).Handler()

	// Loopback-only is on: a non-loopback origin is refused before auth.
	req := httptest.NewRequest("POST", "/v1/admin/devices/revoke", strings.NewReader(`{"deviceId":"x"}`))
	req.RemoteAddr = "203.0.113.5:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("non-loopback admin = %d, want 403", rr.Code)
	}

	// From loopback but unsigned, it reaches auth and is rejected there.
	req2 := httptest.NewRequest("POST", "/v1/admin/devices/revoke", strings.NewReader(`{"deviceId":"x"}`))
	req2.RemoteAddr = "127.0.0.1:5555"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("loopback unsigned admin = %d, want 401", rr2.Code)
	}
}
