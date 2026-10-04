# Sentinel // Remote Operator

A personal remote-management system for computers the owner controls.

- **SENTINEL** — the Windows-side agent (this repository's `agent/`).
- **OPERATOR** — the native iPhone client (later milestones).

Sentinel is a real administration tool, not a simulated hacker terminal. Every
displayed value is real; unavailable data is reported as `UNAVAILABLE`, never
invented. The agent operates quietly but remains identifiable under its own
name in Services and Task Manager, and never masquerades as another process,
bypasses OS privacy/security controls, or performs surveillance beyond the
owner-initiated actions described here. See
`Sentinel_Operator_Master_Build_Spec` for the full product specification.

## Milestone status

This repository currently implements **Milestone 0** (repository structure,
config model, audit logging, test harness) and **Milestone 1** (Windows agent:
real status, activity/idle, lock, mute, PANIC sequencing, and local
authentication). Later milestones — secure pairing/transport, the SwiftUI
Operator client, Grab Screen, Sentinel arm/disarm events, Terminal, and service
packaging — are not yet built.

## Repository layout

```
agent/                      Windows SENTINEL agent (Go)
  cmd/sentinel-agent/        CLI entrypoint: run, credential, version
  internal/
    config/                  typed configuration model + load/save
    audit/                   append-only audit log (daily files + ring buffer)
    auth/                    HMAC request signing, replay protection, credential store
    platform/                host-capability interface + Windows and stub implementations
    control/                 PANIC preset sequencing
    api/                     authenticated HTTP control surface
    agent/                   process wiring and lifecycle
```

The agent's own build, run, and development instructions are in
[`agent/README.md`](agent/README.md).
