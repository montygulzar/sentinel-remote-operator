# Sentinel // Remote Operator

A personal remote-management system for computers the owner controls.

- **SENTINEL** — the Windows-side agent (this repository's `agent/`).
- **OPERATOR** — the native iPhone client (this repository's `operator/`).

Sentinel is a real administration tool, not a simulated hacker terminal. Every
displayed value is real; unavailable data is reported as `UNAVAILABLE`, never
invented. The agent operates quietly but remains identifiable under its own
name in Services and Task Manager, and never masquerades as another process,
bypasses OS privacy/security controls, or performs surveillance beyond the
owner-initiated actions described here. See
`Sentinel_Operator_Master_Build_Spec` for the full product specification.

## Milestone status

This repository currently implements:

- **Milestone 0** — repository structure, config model, audit logging, test harness.
- **Milestone 1** — Windows agent: real status, activity/idle, lock, mute, PANIC sequencing, local authentication.
- **Milestone 2** — secure remote transport and device pairing: an owner-initiated, expiring pairing flow; a protected authorized-device registry supporting multiple devices; per-device HMAC authentication with replay/stale/tamper protection; immediate revocation; a configurable bind address; and an audit trail for pairing, authentication and revocation.
- **Milestones 3 & 4 (Operator Alpha + Grab Screen)** — the native SwiftUI Operator client (`operator/`): Keychain-backed pairing, signed requests using the Milestone 2 device identity, a real Home status screen with an explicit offline state, the INTEL shell, a functional PANIC hold-to-confirm, and end-to-end **Grab Screen** backed by a new authenticated `GET /v1/screen/grab` agent endpoint (in-memory GDI capture, binary image + metadata, no disk artifacts). A locked cross-language signing-vector file pins the Go agent and the Swift Operator to byte-identical request authentication.

**Verification status.** The Go agent logic, tests and Windows cross-compile are
verified here. Windows screen capture is `IMPLEMENTED — NEEDS WINDOWS
VERIFICATION` (the GDI pixel grab runs only on Windows). The entire SwiftUI
Operator is `IMPLEMENTED — NEEDS XCODE/iOS VERIFICATION`: it was authored
without an Apple toolchain and has not been compiled or run — build and test it
on a Mac (see [`operator/README.md`](operator/README.md)).

Later milestones — Live Screen, camera/location, Sentinel arm/disarm events,
Terminal, and service packaging — are not yet built.

## Repository layout

```
agent/                      Windows SENTINEL agent (Go)
  cmd/sentinel-agent/        CLI entrypoint: run, pair, devices, revoke, version
  cmd/genvec/                dev tool: regenerate the signing test vectors
  internal/
    config/                  typed configuration model + load/save
    audit/                   append-only audit log (daily files + ring buffer)
    auth/                    HMAC request signing, replay protection, credential store
    platform/                host-capability interface + Windows and stub implementations
    screen/                  platform-independent frame encoding (JPEG/PNG)
    control/                 PANIC preset sequencing
    api/                     authenticated HTTP control surface
    agent/                   process wiring and lifecycle
operator/                   native iOS OPERATOR client (Swift / SwiftUI)
  Sources/SentinelKit/       testable logic: signing, client, Keychain, pairing
  Tests/SentinelKitTests/    XCTest suite incl. shared signing vectors
  App/                       SwiftUI app target (assembled in Xcode)
```

The agent's own build, run, and development instructions are in
[`agent/README.md`](agent/README.md).
