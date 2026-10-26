# Tasks and acceptance

- [x] MAC-REC-01/02/03: Ruby recovery owner, exact inlet plan, controlled admission and lifecycle fences; `daemon/test_ordered_recovery.rb` exercises real activation/cleanup with simulated process I/O and clock.
- [x] MAC-REC-04: SwiftUI home card, authenticated controls and optional status decoding; `RecoveryTests.swift` covers old-response compatibility and progress semantics.
- [x] MAC-REC-05: allowlisted path/probe/interface events; deterministic interface transition test.
- [x] Local final regression: Ruby 268 tests / 2294 assertions, shared 24 / 172, staged payload 268 / 2294; Swift 100 pass. Three real-window Dock tests intentionally excluded on the working desktop. Counts and logs recorded in private verification; these are synthetic/source checks.
- [x] Final implementation cloud checks: run 39896639191 at 6943740b88dc886eae7c7fec0714c82837baac59, all seven checks PASS, installer SKIPPED and artifacts zero. Any later source SHA needs its own recorded verification; no Windows package/install.
- [ ] Separate local candidate/install/egress acceptance, if performed under deployment authorization. Do not mark policy simulation as live failover acceptance.

OpenSpec Markdown change only; no CLI validation or archive has been run.

- [x] MAC-REC-06: Preserve the health owner through resume probe errors and unexpected iteration errors; allow explicit retry through the resume activation contract and clear pending only after verified commit; avoid false preserved outcomes. Four isolated regression cases, no production fault injection.
- [ ] Separate installed acceptance for MAC-REC-06; source tests do not restart an existing dead monitor.

- [x] MAC-REC-07: paced background observations and automatic catalogue requests, isolated candidate timeout, exhausted-round backoff, fresh-success state reconciliation, bounded failure summary and passive SS/WG decoder. Deterministic daemon suite: 313 tests / 2551 assertions. Protocol fixtures are synthetic, not live tunnel acceptance.
- [ ] MAC-REC-07 installed acceptance and live passive packet acceptance; capture requires host permission. No historical missing packet evidence can be reconstructed by new instrumentation.

- [x] MAC-REC-08: independent local recorder, strict WG event allowlist, physical-interface UDP counters, stale-status continuity, bounded first/latest incident snapshots and singleton loop. Eight isolated tests / 37 assertions; diagnostic exporter StatusReadTests 20 passed without live window tests.
- [x] Separate recorder-only deployment/readback: natural handshake initiation and authenticated response plus physical UDP RX/TX observed; existing adapter/core PIDs unchanged. This is observation acceptance, not a new outage/recovery test or installation of MAC-REC-07 daemon changes.
- [ ] Future natural outage evidence and actual login/reboot restart acceptance; no sleep, forced disconnection or reboot performed.
# 2026-10-26 bounded HTTPS destination recovery

- [x] MAC-REC-09: Recover missing public TLS names in the worker; preserve existing WG resolver/rules and explicit-domain/private/non-TLS paths. Add real-engine loopback fixtures and macOS IPv6 echo argument regression.
- [ ] MAC-REC-09: Installed current-build observation of user-initiated requests; record separately from local fixtures and neutral endpoint verification. No sleep or physical network fault injection.

## 2026-10-26 catalogue and SS-first recovery

- [x] MAC-REC-10: Authorized/coalesced manual catalogue update and independent progress; atomic cache, in-memory fallback and address-family validation.
- [x] MAC-REC-10: Combine official dedicated/main-address SS tuples, deduplicate and rotate fallback windows; SS city stages before native-family fallback, exact explicit modes, and bounded preservation on restart.
- [x] Main-window/browser update controls, visible update/cache failures, and explicit native fallback progress. Ruby/Swift regression and release build are recorded separately from installed acceptance.
- [ ] Live full exhaustion, manual physical network fault, long-duration stability and Windows parity of the new policy (not part of this local Mac update).
