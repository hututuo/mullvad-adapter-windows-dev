# Mac feature parity work list

This is an implementation inventory, not a claim of installed or live-network
acceptance. The SwiftUI/Ruby Mac path and Tauri/Rust Windows path have separate
lifecycle and platform boundaries.

| Area | Mac implementation | Remaining work and acceptance |
| --- | --- | --- |
| Existing account | Always-visible account login; saved-account management independent of tunnel identity; official list/expiry, bounded TLS route discovery, fresh/cached/error evidence, confirmed key view, voucher and management logout | Synthetic contracts cover refresh failure, account coherence and revoked-device handling; installed controls and real mutations require separate acceptance |
| Local device | Keychain-first X25519 generation, durable draft and official address receipt; explicit first install, save a newly registered device as another local identity, explicit activation after old workers drain | No automatic key rotation or device revocation; preserve legacy templates and uncertain drafts. Real replacement, rollback and egress acceptance are separate gates |
| Stop and quit | Global asynchronous stop cancels connection work, closes owned front/workers, persists stopped intent and retains account management; quit waits for confirmed stop | Process cleanup, persistence failures and stale receipts are covered by synthetic tests; no system-wide firewall or installed-process acceptance is claimed |
| Clean first run | Account-only `needs_setup`, no implicit legacy profile or new-user relay/proxy, explicit first identity install then normal catalogue/front lifecycle | Real clean-machine installer, Keychain persistence and city/egress acceptance remain separate gates |
| Independent Clash profile | Shared Rust portable-profile generator and Windows product integration exist | Mac API/UI integration with persistent loopback subscription, official Clash import URI and index/file readback; preserve current selection, existing subscriptions and undo boundaries |
| Routing choices | Mac adapter owns its local tunnel; existing external Clash still owns ingress | In the independent profile, domestic/LAN direct, AI and ordinary external traffic default Mullvad; allow explicit existing-node/provider choice and a separate API route, including empty-subscription state |
| Diagnostics | Local status, city/recovery evidence and redacted private reports | Add profile import/readback, API route/provenance and identity-install facts without collecting account state, keys or raw authenticated replies; distinguish generated profile from actual selected profile/egress |
| Maintenance priority | Existing operation gate and generation/epoch recovery guards | Audit Mac background ICMP/process queue cancellation so explicit connection intent outranks maintenance without releasing ownership before the native process ends |
| Transport | Mac SS/direct, multihop and single-hop PQ have their own implementation boundaries | Preserve API-sourced relay/key/address/SS endpoint data; independent carrier/physical-routing/engine work is required for UDP-over-TCP, QUIC, LWO and DAITA |

Saved identity activation drains old workers and commits the chosen local
profile explicitly; saving a newly registered profile does not activate it.
Automatic rotation remains unimplemented. Failure and crash recovery must
preserve the previous key without automatically reusing a revoked identity or
replaying registration. The implemented archive applies only to a draft already proven to
be the installed identity; an unactivated created or addressless registered draft
still blocks another creation on its account. Listing a registered key alone
cannot supply tunnel addresses or prove an activated connection.

Follow that with the independent Clash profile integration and selected-profile
readback. The routing policy is shared source, while macOS URI handling, profile
discovery and lifecycle need platform validation. Diagnostics and maintenance
priority should accompany that tranche. Unsupported carrier work must not be
presented as a configuration-only parity fix.
