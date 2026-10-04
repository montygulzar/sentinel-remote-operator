# SENTINEL Agent

The Windows-side agent for Sentinel // Remote Operator. It exposes a narrow,
fully authenticated HTTP control surface that the Operator client uses to read
real host status and perform deliberate actions.

Built with Go. The only external dependency is `golang.org/x/sys` (Win32
syscall bindings, used only by the Windows build); everything else — HTTP,
JSON, HMAC authentication — is standard library.

## Design

All operating-system access goes through the `platform.Provider` interface.
The real implementation (`provider_windows.go`, `audio_windows.go`) compiles
only on Windows; a non-Windows stub lets the agent build and its API be
exercised during development, reporting `UNAVAILABLE`/`ErrUnavailable` rather
than fabricating host data. This keeps the agent's logic — authentication,
PANIC sequencing, audit logging, status assembly — testable on any platform.

## Build

```sh
# Native (development) build for the current OS:
go build ./cmd/sentinel-agent

# Production build for a Windows host:
GOOS=windows GOARCH=amd64 go build -o SentinelAgent.exe ./cmd/sentinel-agent
```

Installation as a quiet (no-console) Windows service, and installer/packaging,
are Milestone 8 and not yet implemented. The binary runs correctly in the
foreground today.

## Run

```sh
sentinel-agent run [-config PATH]
```

On first run the agent writes a default config and generates a device
credential. The default config path and data directory are platform-specific;
on Windows the data directory is `C:\ProgramData\Sentinel` (config, credential,
and `Logs\`).

By default the control API binds to `127.0.0.1:8787`. Remote reachability is
intended to be provided by a private overlay network (e.g. Tailscale) plus
Sentinel's own authentication — never by exposing an unauthenticated endpoint
to the public Internet.

## Pairing an Operator

An Operator joins by pairing, initiated by the owner on the local machine:

```sh
sentinel-agent pair [-config PATH]     # opens a window, prints a one-time code
sentinel-agent devices [-config PATH]  # lists authorized devices (no secrets)
sentinel-agent revoke -id <deviceId>   # revokes a device immediately
```

`pair` opens a short-lived pairing window and prints a one-time code for the
owner to enter into their Operator. The Operator then calls `POST /v1/pair`,
signing the request with the code. On success Sentinel registers a new device
and both sides independently derive the permanent per-device key from the code
and two exchanged nonces — the key is **never transmitted**. Each device gets a
stable id; many devices are supported; any one can be revoked.

These owner commands talk to the running agent over loopback and authenticate
with the owner/admin key read from the protected local store. No permanent
device secret is ever printed or logged; the only material shown is the
ephemeral pairing code.

## Configuration

Configuration is JSON. Defaults are written on first run; unknown fields are
rejected to catch typos. Example:

```json
{
  "deviceName": "",
  "listen": "127.0.0.1:8787",
  "dataDir": "C:\\ProgramData\\Sentinel",
  "adminLoopbackOnly": true,
  "panic": { "closeApps": ["chrome.exe", "slack.exe"] },
  "auth": { "timestampSkew": "30s" },
  "pairing": { "ttl": "5m" },
  "log": { "retentionDays": 30 }
}
```

- `deviceName` — overrides the reported host name; empty uses the real one.
- `listen` — bind address. Default is loopback; set to an overlay-network
  address (e.g. the host's Tailscale IP) for remote reach. Binding beyond
  loopback is logged; authentication is required regardless of where the agent
  binds.
- `adminLoopbackOnly` — when true (default), owner/admin endpoints (pairing,
  device management) are accepted only from the local machine, so pairing and
  revocation cannot be driven remotely even with the admin key.
- `panic.closeApps` — executable image names closed by PANIC, in order.
- `auth.timestampSkew` — maximum accepted age/future-dating of a signed request.
- `pairing.ttl` — how long an owner-initiated pairing window stays open.
- `log.retentionDays` — daily log files older than this are deleted (0 keeps all).

## Authorized devices and transport

Authorized Operator devices live in a registry at `dataDir/devices.json`; each
per-device key is encrypted at rest (DPAPI local-machine scope on Windows;
owner-only file permissions elsewhere during development). The owner/admin key
in `dataDir/admin.key` is protected the same way. Secrets are never logged and
never returned by any endpoint.

Remote reach is intended to come from a private overlay network (e.g.
Tailscale) plus Sentinel's own authentication. Sentinel does not open router
ports, use UPnP, or create public tunnels, and network membership alone never
grants access — every request is independently authenticated.

## Authentication

Every request must be signed (spec §13). Authorisation is never granted on
network membership alone. Requests carry four headers:

| Header | Meaning |
| --- | --- |
| `X-Sentinel-Device` | device ID from the credential |
| `X-Sentinel-Timestamp` | unix seconds |
| `X-Sentinel-Nonce` | unique per request |
| `X-Sentinel-Signature` | lowercase hex HMAC-SHA256 (see below) |

The signature is `HMAC-SHA256(key, canonical)` where `canonical` is these six
lines joined by `\n`:

```
<deviceId>
<METHOD (upper-case)>
<request target: path and query, e.g. /v1/logs?limit=50>
<timestamp>
<nonce>
<hex(sha256(body))>
```

The key is the per-device key for device requests, the admin key for
`/v1/admin/*` requests, and the one-time code for `/v1/pair`. The server rejects
(HTTP 401) an unknown device, a revoked device, a bad signature, a timestamp
outside `timestampSkew`, or a reused nonce — all with the same opaque message so
a caller cannot distinguish the cause. Nonce replay protection is namespaced per
principal and consumed atomically, so concurrent replays of one request yield at
most one success.

## Grab Screen

`GET /v1/screen/grab` captures a single frame of a display into memory, encodes
it, and returns it directly as the response body (spec §5, §11). The flow is
capture → memory → encode → transmit → discard: no screenshot file is ever
written to disk, and nothing lands in Desktop, Downloads or Pictures. On
Windows the capture uses the documented GDI `BitBlt` path (a normal, supported
mechanism — not a graphics hook and not a secure-desktop grab); a surface the OS
protects comes back blank or fails, and that is reported honestly rather than
bypassed.

- `display` (optional) selects a display by id; the primary display is the
  default. `GET` the grab response headers to see which display was captured;
  multi-display selection is built in but the Operator currently uses the
  primary. Capture is `IMPLEMENTED — NEEDS WINDOWS VERIFICATION` (the pixel grab
  runs only on Windows; its logic, routing and encoding are tested on any host
  via the fake provider).
- `format` is `jpeg` (default) or `png`; `quality` is `1..100` for JPEG.
- Success is `200` with an `image/jpeg` or `image/png` body and
  `X-Sentinel-Capture-Display/Width/Height/Format/Timestamp/Ms` plus
  `X-Sentinel-Encode-Ms` headers. A capture the host cannot perform returns a
  non-2xx JSON rejection (`503` unavailable, `404` unknown display), never a
  blank success.

## API (Milestone 1 subset)

A 2xx response means the request was accepted and processed; its body carries
the structured result (an action that the host could not perform returns 200
with `{"ok": false, "error": "..."}`). A non-2xx response means the request was
rejected (401 auth, 400 malformed, 404/405 routing).

| Method & path | Purpose |
| --- | --- |
| `GET /v1/status` | device name, session lock state, idle/uptime seconds, CPU/RAM/battery percent (null when unavailable) |
| `GET /v1/activity` | session state, foreground app, idle seconds |
| `GET /v1/logs?limit=&class=` | recent audit events, optionally filtered by class |
| `GET /v1/screen/grab?display=&format=&quality=` | capture one current screen frame and return it as a binary image (default JPEG) with capture metadata in `X-Sentinel-Capture-*` headers |
| `POST /v1/control/lock` | lock the workstation |
| `POST /v1/control/mute` | mute system audio; body `{"muted":false}` unmutes |
| `POST /v1/control/panic` | run the PANIC preset: close configured apps, volume → 0, lock; returns per-step results (per-application detail under the close step) |

Pairing and owner/admin surface:

| Method & path | Auth | Purpose |
| --- | --- | --- |
| `POST /v1/pair` | pairing code | complete pairing; returns the new device id and key-derivation material |
| `POST /v1/admin/pairing/start` | admin + loopback | open a pairing window; returns the one-time code |
| `POST /v1/admin/pairing/cancel` | admin + loopback | close the pairing window |
| `GET /v1/admin/devices` | admin + loopback | list authorized devices (no secrets) |
| `POST /v1/admin/devices/revoke` | admin + loopback | revoke a device by id, effective immediately |

## Testing

```sh
go test ./...            # all unit and integration tests
go test -race ./...      # with the race detector

# Confirm the Windows build and vet cleanly from any host:
GOOS=windows GOARCH=amd64 go vet ./...
```

Tests cover authentication (valid / forged / tampered / stale / replayed /
unknown-device / revoked requests, concurrent-replay races), device pairing
(success, expiry, wrong-code attempt cap, single-use, replay, key-derivation
parity, no-secrets-in-logs), the device registry (multi-device isolation,
revocation, protected persistence round-trip), PANIC sequencing (ordering,
attempting every configured app despite individual failures, still muting and
locking after a close failure), audit logging (format, rotation, retention, ring
buffer), and the full HTTP surface end-to-end including pairing, immediate
revocation and the admin loopback restriction.

Grab Screen is covered too: the endpoint's authentication (an unsigned request
is rejected and never triggers a capture), image encoding/decoding round-trips,
the primary-display default and explicit display selection, an invalid display
(404), honest capture-error propagation (503), format/quality validation, and a
check that a normal grab leaves no image artifact anywhere in the agent's data
tree.

The request-signing algorithm is pinned by a shared, locked vector file
(`internal/auth/testdata/signing_vectors.json`): `TestSigningVectorsAreReproducedExactly`
holds the Go agent to it, and the Swift Operator's suite holds the client to the
same bytes, so the two languages are guaranteed to produce identical signatures.
Regenerate the vectors (only when the algorithm deliberately changes) with
`go run ./cmd/genvec`.
