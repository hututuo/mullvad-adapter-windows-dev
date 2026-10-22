# Tasks

- [x] WO-1/2: Classify local DNS/HTTPS pre-CONNECT failures; retain diagnostics and independent positive traffic; regression-test thread cleanup and ownership rejection.
- [x] WO-3: Share startup deadline with read-only controller requests, mixed-listener connects and chain resolution; test expired/no-I/O and slow-body/later-request behavior.
- [x] Run locked local core regressions (441 passed) and Windows API feature checking (typecheck on macOS, not Windows runtime).
- [ ] Run tests-only cross-platform CI on the pushed source SHA; record results privately.

No packaging, installation, live tunnel/network changes or OpenSpec CLI archival is part of this change.
