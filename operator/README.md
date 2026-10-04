# OPERATOR — native iOS client

The native SwiftUI Operator for Sentinel // Remote Operator. It pairs with a
Windows SENTINEL agent, reads real status, grabs a current screen frame, and
secures the workstation with PANIC — all over the owner's private network, with
every request signed by the same per-device key the agent expects.

> **Verification status.** This target is `IMPLEMENTED — NEEDS XCODE/iOS
> VERIFICATION`. It was authored in a Linux environment with no Swift/Xcode
> toolchain, so it has not been compiled or run here. The platform-independent
> logic lives in `SentinelKit` and its XCTest suite; build and run those on a
> Mac to verify.

## Layout

```
operator/
  Package.swift                 SwiftPM package: SentinelKit library + tests
  Sources/SentinelKit/          all non-UI logic (compiles with `swift build`)
    Signing.swift               canonical request signing (mirrors the Go agent)
    Models.swift                typed API models (Status, PanicResult, …)
    Credential.swift            PairedDevice + CredentialStore protocol
    KeychainCredentialStore.swift   Keychain-backed store (iOS/macOS)
    Endpoint.swift              address parsing + request-target building
    RequestBuilder.swift        shared signed-URLRequest builder
    SentinelAPI.swift           the typed client protocol
    SentinelClient.swift        URLSession client; signs every request
    ScreenMetadata.swift        Grab Screen header parsing
    Pairing.swift               pairing handshake + key derivation
    ConnectionState.swift       online/offline model
    HomeModel.swift             Home view model (real status / offline)
    PanicController.swift       hold-to-confirm PANIC state machine
  Tests/SentinelKitTests/       XCTest suite (NEEDS XCODE/iOS to run)
    Resources/signing_vectors.json   shared cross-language signing vectors
  App/                          SwiftUI iOS app target (assembled in Xcode)
    SentinelOperatorApp.swift   @main
    AppModel.swift              root state (credential, client)
    Theme.swift, Haptics.swift  design + haptics
    PairingView.swift, HomeView.swift, IntelView.swift,
    GrabScreenView.swift, PanicButton.swift, LogsView.swift,
    NotAvailableView.swift, Components.swift
```

`SentinelKit` holds everything testable; `App/` is the thin SwiftUI layer that
needs Xcode. This split means `swift test` on a Mac exercises signing, models,
pairing math, Keychain, the connection/offline logic and the PANIC state
machine without an iOS simulator.

## Verifying the logic (`swift test`)

On a Mac with the Swift toolchain:

```sh
cd operator
swift test
```

This runs, among others:

- **SigningVectorsTests** — reproduces every locked signature in
  `Resources/signing_vectors.json`. These are the *same* vectors the Go agent
  verifies (`agent/internal/auth/testdata/signing_vectors.json`), so a pass on
  both sides proves byte-identical request authentication across the two
  languages. The expected signatures are fixed values computed by the verified
  Go implementation, not generated at test time.
- **PanicControllerTests** — a cancelled hold sends zero PANIC requests; a
  completed hold sends exactly one; a partial failure never reports SECURED.
- **HomeModelTests** — real status decodes; an unreachable agent yields OFFLINE
  and drops stale telemetry.
- **ScreenMetadataTests**, **ModelDecodingTests**, **CredentialAndPairingTests**.

## Building the iOS app (Xcode)

There is intentionally no checked-in `.xcodeproj` (a hand-written project file
cannot be validated in this environment). To build the app on a Mac:

1. Open Xcode → **File ▸ New ▸ Project… ▸ iOS App** (SwiftUI, Swift). Target iOS 16+.
2. **File ▸ Add Package Dependencies… ▸ Add Local…** and select the `operator/`
   folder, adding the `SentinelKit` library to your app target.
3. Delete the template `ContentView.swift`/`App.swift`, then drag the files from
   `operator/App/` into the app target (Copy if needed).
4. In the target's **Info** settings add:
   - **App Transport Security** — the agent serves plain HTTP over the private
     overlay. Add `NSAppTransportSecurity` → `NSAllowsLocalNetworking = YES`
     (preferred for LAN/Tailscale), or an explicit exception for your agent host.
   - **`NSLocalNetworkUsageDescription`** — e.g. "Sentinel connects to your own
     workstation on your private network."
5. Build and run on your iPhone.

Transport confidentiality is provided by the private overlay network (e.g.
Tailscale); request integrity and authorization are provided by Sentinel's own
signatures. Network membership alone is never authorization.

## Pairing

On the Windows host, open a pairing window:

```sh
sentinel-agent pair
```

It prints a one-time code. In Operator, enter the agent address
(`<tailscale-ip>:8787`) and the code, then tap **PAIR**. The permanent
per-device key is derived locally on both sides from the code and two exchanged
nonces — it is never transmitted — and stored in the iOS Keychain. The Operator
also verifies the agent's proof-of-code before trusting the pairing, so a
network attacker who never saw the code cannot complete it.
