# Tasks

- [x] RT-1: parent-owned subprocess deadline/output/cancellation cleanup, fake hung child and inherited pipe regression.
- [x] RT-2: aggregate deadline, controller ownership budget, local failure classification and active-path preservation regressions.
- [x] RT-3: alternate-service check and selective target failure regression; retain existing two-failure repair and stale-context tests.
- [x] RT-4: named local timeout events and numeric phase timing.
- [ ] Fresh installed-runtime acceptance and incident correlation. Not run: the user currently requests tests only, with no packaging or installation.

This is a hand-maintained incremental specification. No OpenSpec CLI validation or archive has been run.

- [x] RT-1/4: Preserve local timeout/cancellation through denied group/child signals, reject positive-PID fallback for reaped leaders, classify spawn/pipe errors locally, and add four permission/cleanup regressions. Installation evidence remains private and distinct from source tests.

- [x] RT-1/4: Decouple deadline/cleanup logs with a bounded single-writer queue; retain probe trace and phase timings, tolerate writer creation failure, and distinguish stale publisher lock contention from scheduling gaps.
- [x] RT-5: Prepare Interactive launch-agent policy only during an authorized upgrade; preserve other configuration and restore original plist on failed/manual rollback. Real plist round-trip tested without loading a job.
- [ ] New installed-runtime acceptance for queued diagnostics and scheduling policy; source tests do not establish the historical cause or authorize replacement.
