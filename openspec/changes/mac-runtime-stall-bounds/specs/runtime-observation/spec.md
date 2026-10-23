# Runtime observation

## RT-1: Bound owned diagnostic commands

WHEN a listener-ownership, config-validation, ping or curl diagnostic stops progressing, THEN the observer enforces a monotonic parent-side deadline, bounds retained stdout/stderr, closes its pipes, and terminates/reaps only its own short-lived process group. It must not signal a pre-existing front or worker. Cancellation follows the same cleanup path. A denied group signal must not
replace the timeout/cancellation or skip bounded reap and pipe closure. A
positive-PID fallback requires an unreaped owned child, revalidated with waitpid;
an already reaped group leader must never be signalled by positive PID. Failure
to signal is recorded as cleanup-deferred, not successful termination. Local
spawn/pipe system errors are indeterminate observations with phase/operation/error
class only, never a negative relay sample or a dump of command arguments. Operating-system scheduling can delay deadline handling; this is not a real-time guarantee.

## RT-2: Bound aggregate canaries

WHEN a leaf probe fails to return, THEN readiness validation stops waiting after a 24-second aggregate budget and full diagnostics after 34 seconds, plus bounded cleanup. Local execution deadlines and unavailable state locks are indeterminate observations, not failed relay/SS samples. Active health defers without incrementing the remote failure streak. A candidate controller deadline preserves the old active worker when one still exists and stops that automatic recovery round without quarantining the candidate.

## RT-3: Preserve a working front

WHEN the literal-IP diagnostic fails but domain HTTPS through the same front succeeds, THEN preserve the front and worker, record diagnostic-target degradation and do not wake tunnel recovery. Only negative observations for both targets can advance the existing front-only repair threshold. Existing context/epoch checks, physical-offline waiting and single-identity ownership remain mandatory. Successful local control HTTP alone never proves external traffic works.

## RT-4: Explain observation latency

WHEN a local command exceeds its deadline, THEN record the named phase, budget and elapsed time without command arguments, credentials or configuration contents. Probe records include available numeric phase durations, including parent command wall time separately from curl's internal time. These records describe evidence, not an inferred universal root cause.

Timeout/cleanup logging and local probe deferrals must not wait for filesystem I/O or the event-file mutex. A single writer accepts at most 128 queued records, retaining observation timestamps and parent operation/recovery/attempt traces. Overflow drops the oldest queued entries and reports the count; abrupt exit may lose queued records. Writer creation failure must not replace a local-indeterminate result. Command telemetry separates spawn, capture and maximum poll gap; synchronous OS spawn and host scheduling are not hard real-time guarantees.

WHEN the status publisher runs but cannot copy state/action data, THEN stale-publication diagnostics identify that reason separately from delayed publisher ticks, rate-limited to one per 30 seconds. Diagnostics must not renew stale evidence or mark the tunnel down.

## RT-5: Classify the interactive network service correctly

WHEN an explicitly authorized daemon upgrade updates the existing owned launch agent, THEN use Interactive rather than Background batch scheduling for the service and its children. Preserve other job settings, back up the complete original plist, and restore its bytes and permissions on installation failure/manual rollback. Read-only checks never update or restart the job. This TCP service does not use XPC activity to become Adaptive. Scheduling classification is not historical incident root-cause proof.
