# Requirements

## NS-1 Stable binding before new work
WHEN physical bindings change while attachment remains Available, THEN cancel old-bound work immediately and wait for SETTLE_MS of fresh unchanged binding observations before new Prepare/Verify. A→B→C changes restart the interval; gaps/unknown never count as stable.

## NS-2 Preserve interrupted intent
WHEN a still-owned candidate is cancelled by binding change without a failed readiness measurement, THEN retry the same relay after clean stop and settling, preserving the remaining queue and original recovery deadline. Explicit manual relay has no alternative relay list. Disconnect, new user selection and identity preemption clear prior intent; measured failures keep existing fallback rules.

## NS-3 DNS-independent API bootstrap
WHEN no explicit bootstrap proxy is configured, THEN connect to the upstream-versioned official API seed with the original HTTPS hostname and normal certificate verification. Do not resolve arbitrary authorities with that seed. Explicit proxy failure never falls back, and mutations are not replayed.

An accepted explicit user intent may wait for physical connectivity until cancelled, disconnected or superseded; it must remain visible and cancellable. The 45-second candidate budget begins only when work starts. A second binding check racing the first must requeue the same accepted relay. An exact relay retries network/stale interruptions only; measured or terminal start failures stop it rather than creating a rapid retry loop.

## NS-4 Verified API address cache and explicit fallback
WHEN official TLS discovery succeeds, THEN persist a bounded validated address list locally and prioritize the last successful direct address on the next operation. Preserve the official seed. After bounded direct failures, try the explicitly selected independent Clash proxy, then a previously healthy front; bootstrap must never depend on an unestablished tunnel. Cache update/preflight use no credentials. Send the account/device operation only on the selected route and never replay mutations.

## NS-5 Classify health failures
WHEN IP or HTTPS still succeeds but DNS or a service check fails, THEN preserve the original path with degradation. Local probe errors or stale evidence do not prove a bad relay. Recheck locally; repeated local failure may rebuild the original path, but must not fabricate negative canary evidence or consume another city candidate. Fresh all-data failure may start original-path recovery. Physical binding change requires rebinding the original path. An expired negative candidate result is retried on the same relay within the original budget.

## NS-8 Classify interface parameters without cancelling healthy work
WHEN a valid interface-parameter notification arrives, THEN keep the selected data plane and existing measurement, while blocking new bound operations and adoption of positive or negative results until the single sampling worker has reread complete interface parameters. Only interface Metric may differ without invalidating continuity; address/route/add/delete/invalid-key notifications, other parameter differences, errors and expired physical evidence retain the hard invalidation path. Compare explicit complete fields, not callback payloads or struct padding.

Classification of an older batch cannot release a newer notification. Waiting cannot extend proof freshness or exceed two seconds. A late notification during witness validation, mailbox consumption, persistence or selector work requires another publication check against the same absolute proof deadline. Cancellation and stop receipts remain drainable. No notification is Internet-readiness evidence; constrained route, source, same-socket and actual canary proofs remain required. Sampling cannot establish the history of a link flap that occurred and reverted between reads.

## NS-9 Quiet healthy monitoring
WHEN a connection passes its health assessment, THEN keep the connected presentation and schedule its next normal full check about 30 seconds after completion. Preserve the two-second confirmation after a first fresh data-plane failure, and existing separate local-error/recovery backoff. A parameter-only hint must not trigger a full tunnel check or a new retry round.
