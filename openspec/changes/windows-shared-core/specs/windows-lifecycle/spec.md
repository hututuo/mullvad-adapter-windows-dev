# Windows lifecycle requirements

Status: PROPOSED. These are target acceptance requirements, not implemented capabilities.

## ADDED Requirements

### Requirement: WL-01 Independent per-user backend

The Windows adapter SHALL run its control backend independently from the UI, as the configured logged-in user in the initial external-Clash mode. It SHALL distinguish UI exit, backend stop and account-management logout. Initial support does not require operation while nobody is logged in.

#### Scenario: User closes or crashes the UI
- **WHEN** the UI exits while a worker is healthy
- **THEN** the backend, front and worker continue independently, and reopening the UI obtains a fresh authoritative snapshot without changing the relay.

#### Scenario: Backend stop and duplicate launch
- **WHEN** the user explicitly stops the backend or a second backend launch is attempted
- **THEN** stop is bounded and only owned engine/helper processes are cleaned up; a second launch does not create a second front or peer owner; external Clash is not silently reconfigured to DIRECT.

#### Scenario: Login-start configuration fails
- **WHEN** creation or registration of login startup fails
- **THEN** the UI reports actual registration/running evidence and the error; a configuration file existing alone is not displayed as enabled.

### Requirement: WL-02 Authorized and versioned control protocol

The backend SHALL use local authenticated OS IPC with explicit access rules, bounded framing, protocol negotiation and typed messages. UI/renderer access SHALL be limited to required commands. Closing a client connection SHALL NOT imply cancelling a committed operation.

#### Scenario: Unauthorized pipe connection
- **WHEN** a remote or non-allowed user/session connects or submits a control/secret request
- **THEN** the backend rejects it without state changes or returning credentials, keys, tokens or private runtime configuration.

#### Scenario: Lost response and reconnect
- **WHEN** an accepted city change loses its UI response and the UI reconnects
- **THEN** the request/operation ID retrieves the same operation; the UI does not blindly submit a second change. A backend restart uses a new boot ID; unknown outcomes, especially account mutations, require reconciliation and are not blindly replayed.

#### Scenario: Incompatible client and oversized payload
- **WHEN** protocol major versions cannot agree or a message exceeds the documented cap
- **THEN** the command is rejected clearly before mutation; ordinary status does not falsely report the network disconnected.

### Requirement: WL-03 Secret and process ownership

Persistent secrets SHALL be protected under the intended user identity and restrictive Windows ACLs. Backend-owned helper stdout and transient worker configurations SHALL be treated as secret, excluded from ordinary events/reports, and cleaned up on completion and on the next safe startup after a crash. Process ownership SHALL use handles/tokens rather than an unqualified PID.

#### Scenario: Backend crash during PQ or candidate configuration
- **WHEN** the backend is forcibly ended during secret creation
- **THEN** restart finds and removes only owned stale transient material, never exposes it in logs, and does not remove current user data or another instance's live configuration.

#### Scenario: Current account logout
- **WHEN** the user clears account management login
- **THEN** credentials and pending reveal state are cleared; the existing WG identity and healthy tunnel are preserved. Key reveal remains explicit and its UI value disappears on focus loss/leave, including late responses.

#### Scenario: Confirmed subsequent device creation
- **WHEN** a user explicitly confirms another local device creation after activating the previous draft, including under another account
- **THEN** the durable identity must match that completed draft before its exact validated DPAPI ciphertext is privately archived and a new key prepared. A created but unactivated draft remains reusable on its original account; unresolved drafts block cross-account replacement and ambiguous mutations are not resubmitted.
- **AND** activation verifies official registration and preserves the previous identity. Any older valid backup is archived before the fixed backup advances; archive conflicts, unsafe objects or failed readback stop replacement without deleting unique key material. Archived ciphertext remains accessible through a validated read-only recovery API.

### Requirement: WL-04 Complete candidate installation and reversible upgrade

A usable Windows candidate SHALL include the UI, backend, pinned engine and supported helper binaries with platform/architecture, source SHA, versions, sizes, SHA256, signing state and license/source information. The installer SHALL handle required runtime components; users SHALL NOT need compilers, Node, Ruby, cargo or npm. External-Clash requirements SHALL be explicit.

#### Scenario: Offline clean Windows machine lacks WebView2
- **WHEN** the complete installer runs without network access and WebView2 is absent
- **THEN** the installer supplies/installs the required runtime or reports a specific supported alternative; it must not claim installation/runtime acceptance based on copying an executable alone.

#### Scenario: Upgrade fails its local canary
- **WHEN** an authorized upgrade fails startup, schema or adapter data-path validation
- **THEN** it restores the exact compatible prior backend/engine and configuration, reports the failure, and never silently lowers saved protection or deletes original data.

#### Scenario: New installation and corrupted saved state
- **WHEN** first-run identity setup or existing-state validation is incomplete
- **THEN** the UI explains the explicit local import/registration requirement or the storage error; it does not invent an account/device, delete data, or silently replace keys.

### Requirement: WL-05 Thin UI and truthful capabilities

The UI SHALL use backend snapshots for relay/city/protection/recovery truth. It SHALL present up to three favorite cities on the first page, current and limited backup evidence within the selected city, and retain full browsing as an advanced entry. Temporary status SHALL use reserved space, and full buttons/cards SHALL be clickable and keyboard-accessible.

#### Scenario: Waiting, degraded or unsupported state
- **WHEN** the backend is waiting for local network, DNS is degraded, or a protection capability is unsupported
- **THEN** the UI shows that specific state without stale green readiness, distinguishes desired/effective protection, and provides actionable evidence/details rather than only a completed-count fraction.

#### Scenario: Required protection is unavailable
- **WHEN** saved PQ/multihop protection cannot be provided by the current backend/package
- **THEN** connection fails explicitly or requests an explicit user policy change; it never silently substitutes an unprotected path. Combined multihop/PQ, DAITA and unverified carriers remain unavailable until separately implemented and accepted.
