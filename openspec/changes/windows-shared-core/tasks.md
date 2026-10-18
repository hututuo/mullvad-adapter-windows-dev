# Windows shared-core implementation tasks

Status: PROPOSED. All implementation tasks below are unchecked. This document is a migration breakdown, not a claim that implementation was authorized or completed in this architecture review. Actual execution progress and evidence are maintained in the private project context; public acceptance contracts stay here.

## P0 Contract freeze before rewriting

- [ ] 0.1 Extract sanitized fixtures for status/cities/operations/protection/relays/account and document old-client compatibility; no live identity or raw logs. Own `core/crates/protocol/fixtures` and existing-client contract tests. WL-02, WL-03, WL-05.
- [ ] 0.2 Build replayable event sequences from controlled tests for offline/unknown/stable resume/DNS-only/metadata withdrawal/stale probe/busy commit/manual preemption/peer ownership. Own domain conformance fixtures. WR-01, WR-02, WR-03.
- [ ] 0.3 Measure baseline queue/probe/commit timing and identify accepted behavior vs known limitations; do not benchmark on a production peer without authorization. WR-03, WR-05.

## P1 Executable Windows skeleton, no live tunnel claim

- [ ] 1.1 Create shared Rust workspace, pure domain and bounded control executor with fake clock/I/O; run shared conformance cases on macOS and Windows. WR-01, WR-02, WR-03.
- [ ] 1.2 Implement independent standard-user agent, authorized/versioned pipe IPC, boot/operation IDs, single-instance and bounded Job Object cleanup. Test unauthorized users/remote pipe, restart/response loss and UI crash. WL-01, WL-02, WL-03.
- [ ] 1.3 Build minimal Tauri UI/bridge with mock snapshots, tray and fixed status/city layout; test full hit regions, keyboard navigation, focus/late-secret-response behavior and no renderer shell. WL-05.
- [ ] 1.4 Build Windows 11 x64 complete skeleton installer including WebView2 handling and start/stop/rollback paths; bind manifest/source/component hashes. WL-04. A mock package is labelled mock; connection acceptance NOT_RUN.

## P2 Shared engine and platform behavior

- [ ] 2.1 Implement Mihomo backend front/slots/transport/profile graph and probe result classes; preserve peer reservations, drain and protection validation, pin/distribute engine. WR-02, WR-03, WR-04, WL-05.
- [ ] 2.2 Implement Windows physical-interface/address observation and explicit route/socket egress binding; test multi-NIC/IPv6/virtual adapters/sleep/DHCP/unknown. Prove no outbound loop through external Clash and no unintended bootstrap fallback. WR-01, WR-02, WR-06.
- [ ] 2.3 Implement atomic settings/history, ACL/DPAPI storage and safe owned-secret crash cleanup; keep old data, test locked files/corruption/failed writes. WL-03, WL-04.
- [ ] 2.4 Implement metadata/account clients, scoped ICMP, readiness, diagnoses, budget/history/retention and export. APIs use explicit route and bounded I/O; full candidates require actual validation. WR-03, WR-04, WR-05.
- [ ] 2.5 Compare Ruby and Rust replay outcomes for all P0 scenarios; prohibit two backends managing the same real front or peer. Preserve unsupported protection and same-city boundaries. WR-01, WR-02, WR-03, WL-05.

## P3 Feature parity and advanced components

- [ ] 3.1 Implement cities/current/backup evidence, full browser, details, account/device/current-public-key matching and report export, distinguishing account login from tunnel connection. WL-03, WL-05, WR-04, WR-05.
- [ ] 3.2 Implement ordinary multihop and Windows PQ helper build/test; real isolated PQ/rollback/crash canary is a separate gate. If unsupported, capability truthfully blocks required policy. WL-04, WL-05, WR-02, WR-03.
- [ ] 3.3 Keep multi-hop+PQ/DAITA/unverified obfuscation unavailable, inventory upstream/engine versions and licenses; no broad official-feature compatibility claim. WL-04, WL-05.

## P4 Candidate and real acceptance

- [ ] 4.1 Extend CI with Windows-hosted domain/IPC/platform/helper and TS checks; keep macOS checks. Candidate build only after required checks; sign/publish are separate gates. WL-04.
- [ ] 4.2 Download exact candidate, verify full SHA/file size/SHA256/platform/helper/sign state and privacy; test install/start/close-UI/reopen/stop/uninstall-preserves-data and upgrade rollback on a clean Windows VM. WL-01, WL-03, WL-04, WL-05.
- [ ] 4.3 After authorization, test external Clash routing, node/WG/SS/ordinary-multihop, selected-city fallback, physical outage/resume, sleep/multi-NIC/IPv6, DNS-only/service failure, stale/manual cancellation and long connections. Record actual recovery timing, IP change and scope of leak guarantees; simulated tests do not satisfy this task. WR-01, WR-02, WR-03, WR-04, WR-05, WR-06.
- [ ] 4.4 Account voucher/device mutation and identity import/registration are explicit transactions with reconciliation evidence, never blind retries or CI secrets. New-account registration remains its own capability unless implemented/accepted here. WL-02, WL-03, WL-04.

## P5 macOS handover after Windows parity

- [ ] 5.1 Implement macOS platform adapter and compatibility API, compare current SwiftUI contract against Rust backend; migrate exact user data only by authorized local transaction with rollback. WL-02, WL-03, WL-04, WR-01, WR-02, WR-03.
- [ ] 5.2 After shared-backend real acceptance, optionally replace SwiftUI with shared Tauri UI and measure UX/resources; retain original until replacement is accepted. WL-01, WL-05.

## Evidence rule

Every completed task links Requirement IDs to exact tests/run IDs/source SHA and actual artifact. PASS, FAIL, NOT_RUN and BLOCKED remain separate. Windows 10/ARM64, clean install, real connectivity, upgrade, signing and release are not accepted from framework support or cloud compilation alone. Do not archive this change until its declared acceptance scope is satisfied or explicitly revised.
