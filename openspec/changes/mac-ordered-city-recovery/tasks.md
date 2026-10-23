# Tasks and acceptance

- [x] MAC-REC-01/02/03: Ruby recovery owner, exact inlet plan, controlled admission and lifecycle fences; `daemon/test_ordered_recovery.rb` exercises real activation/cleanup with simulated process I/O and clock.
- [x] MAC-REC-04: SwiftUI home card, authenticated controls and optional status decoding; `RecoveryTests.swift` covers old-response compatibility and progress semantics.
- [x] MAC-REC-05: allowlisted path/probe/interface events; deterministic interface transition test.
- [x] Local final regression: Ruby 267 tests / 2290 assertions, shared 24 / 172, staged payload 267 / 2290; Swift 100 pass. Three real-window Dock tests intentionally excluded on the working desktop. Counts and logs recorded in private verification; these are synthetic/source checks.
- [ ] Run exact-commit cloud checks; no Windows package/install.
- [ ] Separate local candidate/install/egress acceptance, if performed under deployment authorization. Do not mark policy simulation as live failover acceptance.

OpenSpec Markdown change only; no CLI validation or archive has been run.
