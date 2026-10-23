# Reliability requirements

## AR-1: Authenticate managed Mac controllers
WHEN a front/worker configuration is generated, THEN it contains a private random
controller secret and internal requests authenticate with that controller's secret.
Public status and logs must not expose the credential.

## AR-2: Own children before waiting
WHEN a worker is spawned or a probe is cancelled at spawn return, THEN ownership
is registered before cancellation can escape. Cleanup must reap the owned process
or retain its reservation on uncertainty; another worker cannot reuse its slot/peer.

## AR-3: Keep local failures indeterminate
WHEN the local SOCKS listener/greeting or probe execution is unavailable, THEN no
negative relay sample is produced. Independent positive data evidence preserves
the path; a measured remote SOCKS rejection remains negative evidence.

## AR-4: Keep control and status paths responsive
WHEN event-file I/O blocks, THEN wake/stop/action acceptance and status response do
not wait for that file mutex. Status writes are deadline-bounded, with request IDs
and numeric phase timings only; stale publications remain visibly stale.

## AR-5: Preserve Windows recovery intent
WHEN a temporary backup/direct/chain trial succeeds, fails or rolls back, THEN the
previous city-level or pinned-relay intent survives. Local asynchronous failures
retain their current target with bounded backoff, rather than spending a candidate.

## AR-6: Fence native chain preparation
WHEN cancellation is acknowledged or a newer intent replaces qualification, THEN
the old native task cannot commit chain configuration. A commit already holding
the durable-write boundary returns busy to cancellation rather than acknowledging
a cancellation it cannot enforce. Legacy manual configuration remains supported.

## AR-7: Export only intended diagnostics
WHEN a Windows report is exported, THEN status excludes device/account identity,
local paths and arbitrary strings, retains allowlisted recovery/probe evidence,
and includes only the existing bounded, validated event history.

## AR-8: Bind candidate origin
WHEN building a Windows candidate, THEN requested SHA equals checkout HEAD;
tracked build inputs and unexpected untracked/ignored inputs are rejected if dirty.
Input changes during the build fail before a successful receipt is written.
