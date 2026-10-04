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

## Provisioning the Operator

Print the device credential to configure an Operator client:

```sh
sentinel-agent credential [-config PATH]
```

This is the only command that emits the secret; it goes to stdout and is never
written to the audit log.

## Configuration

Configuration is JSON. Defaults are written on first run; unknown fields are
rejected to catch typos. Example:

```json
{
  "deviceName": "",
  "listen": "127.0.0.1:8787",
  "dataDir": "C:\\ProgramData\\Sentinel",
  "panic": { "closeApps": ["chrome.exe", "slack.exe"] },
  "auth": { "timestampSkew": "30s" },
  "log": { "retentionDays": 30 }
}
```

- `deviceName` — overrides the reported host name; empty uses the real one.
- `panic.closeApps` — executable image names closed by PANIC, in order.
- `auth.timestampSkew` — maximum accepted age/future-dating of a signed request.
- `log.retentionDays` — daily log files older than this are deleted (0 keeps all).

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

The server rejects (HTTP 401) an unknown device, a bad signature, a timestamp
outside `timestampSkew`, or a reused nonce — all with the same opaque message so
a caller cannot distinguish the cause.

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
| `POST /v1/control/lock` | lock the workstation |
| `POST /v1/control/mute` | mute system audio; body `{"muted":false}` unmutes |
| `POST /v1/control/panic` | run the PANIC preset: close configured apps, volume → 0, lock; returns per-step results |

## Testing

```sh
go test ./...            # all unit and integration tests
go test -race ./...      # with the race detector

# Confirm the Windows build and vet cleanly from any host:
GOOS=windows GOARCH=amd64 go vet ./...
```

Tests cover authentication (valid/forged/tampered/stale/replayed requests and
the credential store), PANIC sequencing (ordering, per-step failure reporting,
securing the host even when a step fails), audit logging (format, rotation,
retention, ring buffer), and the full HTTP surface end-to-end.
