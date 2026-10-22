# Runtime observation requirements

## WO-1: Local unavailability is not relay failure

WHEN the local listener cannot connect, its initial SOCKS greeting fails or its
retained process is unavailable, THEN retain a local-unavailable phase result.
If no independent traffic probe succeeds, return LocalFailure without a negative
relay canary. Upstream CONNECT/TLS/HTTP/DNS rejection remains negative path evidence.

## WO-2: Preserve independent success and security fences

WHEN an IP or hostname traffic probe succeeds and another local phase is
unavailable, THEN use the existing Ready/degraded matrix. Ownership rejection,
process death, cancellation, epoch changes or stale evidence must still prevent
publication. All started sibling probes finish cleanup before return.

## WO-3: Nested work shares startup time

WHEN startup has a remaining budget shorter than a leaf operation's normal
budget, THEN limit that controller read, mixed-listener connection or chain
resolution to the remaining time. Expired work must not connect/enqueue and late
resolver data must not be accepted. Later ordinary controller reads must still
work. Uninterruptible native calls and owned cleanup are explicit limits, not
reasons to detach probes or weaken peer ownership.
