# Tasks

- [x] SS-1: Complete Mac/Windows candidate generation, exact recovery and counts.
- [x] Q-1/Q-2: Pinned carrier, bounded IPC, metadata and socket-binding validation.
- [x] Q-3/Q-4: Both lifecycle owners, canaries, cleanup and cancellation tests.
- [x] Q-5/Q-6: Recovery order, UI/status/log semantics and secret redaction.
- [x] Q-7: Optional runtime manifest component and future assembly inputs.
- [ ] Run targeted local and cross-platform CI checks; bind evidence to source SHA.
- [ ] Live QUIC egress/TUN/natural recovery: separate acceptance, not source tests.

No OpenSpec CLI initialization, formal validation or archive is implied.

Local helper, Ruby, shared-core, desktop and packaging-fixture regressions passed. Isolated Mac QUIC IP, inner DNS and neutral HTTPS passed using an independent test identity. The production program was not replaced. Windows live QUIC, TUN/natural recovery and long-duration acceptance are NOT_RUN. Cross-platform CI is recorded separately after the final integration commit.
