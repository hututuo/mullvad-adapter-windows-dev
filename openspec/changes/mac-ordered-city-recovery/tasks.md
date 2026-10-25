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
