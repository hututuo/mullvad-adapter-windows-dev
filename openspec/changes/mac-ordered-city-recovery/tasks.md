# Tasks and acceptance

- [x] MAC-REC-01/02/03: Ruby recovery owner, exact inlet plan, controlled admission and lifecycle fences; `daemon/test_ordered_recovery.rb` exercises real activation/cleanup with simulated process I/O and clock.
- [x] MAC-REC-04: SwiftUI home card, authenticated controls and optional status decoding; `RecoveryTests.swift` covers old-response compatibility and progress semantics.
- [x] MAC-REC-05: allowlisted path/probe/interface events; deterministic interface transition test.
- [x] Local final regression: Ruby 268 tests / 2294 assertions, shared 24 / 172, staged payload 268 / 2294; Swift 100 pass. Three real-window Dock tests intentionally excluded on the working desktop. Counts and logs recorded in private verification; these are synthetic/source checks.
- [x] Initial exact-commit cloud checks: run 39895875273 at 92739e346b46884c2a97bfdcb3f806f9277aad32, all seven checks PASS, installer SKIPPED and artifacts zero. Any later source SHA needs its own recorded verification; no Windows package/install.
- [ ] Separate local candidate/install/egress acceptance, if performed under deployment authorization. Do not mark policy simulation as live failover acceptance.

OpenSpec Markdown change only; no CLI validation or archive has been run.
