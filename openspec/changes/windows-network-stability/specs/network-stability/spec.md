# Requirements

## NS-1 Stable binding before new work
WHEN physical bindings change while attachment remains Available, THEN cancel old-bound work immediately and wait for SETTLE_MS of fresh unchanged binding observations before new Prepare/Verify. A→B→C changes restart the interval; gaps/unknown never count as stable.

## NS-2 Preserve interrupted intent
WHEN a still-owned candidate is cancelled by binding change without a failed readiness measurement, THEN retry the same relay after clean stop and settling, preserving the remaining queue and original recovery deadline. Explicit manual relay has no alternative relay list. Disconnect, new user selection and identity preemption clear prior intent; measured failures keep existing fallback rules.

## NS-3 DNS-independent API bootstrap
WHEN no explicit bootstrap proxy is configured, THEN connect to the upstream-versioned official API seed with the original HTTPS hostname and normal certificate verification. Do not resolve arbitrary authorities with that seed. Explicit proxy failure never falls back, and mutations are not replayed.

An accepted explicit user intent may wait for physical connectivity until cancelled, disconnected or superseded; it must remain visible and cancellable. The 45-second candidate budget begins only when work starts. A second binding check racing the first must requeue the same accepted relay. An exact relay retries network/stale interruptions only; measured or terminal start failures stop it rather than creating a rapid retry loop.
