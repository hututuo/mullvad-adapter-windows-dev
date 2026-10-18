# A single state owner with a worker-owned front resource

ResourceOwner wraps ObservedOwner and one optional lifecycle worker. Start captures
its domain boot/generation/epoch/operation/path token, rejects an offline latch or
an occupied/failed slot, and constructs the resource on the I/O thread. The resource
need not be Send; process handles and secret input leases never cross back to the
state owner. Only bounded Ready/Finished events cross a capacity-two mailbox.

Every owner poll first applies physical observations, then invalidates a resource
whose token is no longer current. Cancellation uses an atomic flag and capacity-one
wake channel. Ready from an old or explicitly cancelled operation is discarded.
A start that returns a resource after cancellation still stops and drops that
resource on its worker. No replacement is admitted until Finished after resource
Drop. Stop/start/worker failure is sticky: this owner refuses replacement until
process restart, because an error is not proof that overlap is safe. Do not bypass
this by constructing replacement owners in the same process.

Owner polling and Drop do not join I/O. Cancellation is cooperative; a blocked
builder or stop retains the occupied slot, and a dropped owner leaves its one
worker to finish and clean up. Resource implementations must bound their I/O,
check cancellation during startup, implement bounded liveness checks, and use
Drop as a final owned-handle cleanup fallback. A worker panic disconnects its
channel and is reported as Worker failure, not readiness. Ready is the successful
startup event, not a guarantee of later process or VPN health; subsequent events
must continue to be polled. Domain Effect values remain returned to the host;
this slice does not execute recovery probes, candidate selection or policy commits.

The Mihomo Front implementation reuses the previously accepted official-front
fixture's joint version/OUT-REJECT/mixed-connected-peer readiness. It serializes
borrowed input into private stdin, launches the owned Job with a clean environment,
checks cancellation/deadline between bounded controller/socket calls, and accepts
readiness only before 15 seconds. That is an acceptance deadline, not hard kernel
cancellation: an in-flight bounded call can return after it, and failed startup
then has a separate five-second whole-Job stop gate. Cleanup failure is distinct.
Executable packaging/hash verification and trusted runtime ancestors remain the
caller's responsibility. Front readiness is not WireGuard or data-plane readiness.

Eight portable tests use actual threads/channels and even non-Send Rc resources:
blocked-start responsiveness, late cancellation, generation rejection, confirmed
outage stop, blocked-stop exclusion until Drop, failed-stop sticky exclusion,
worker panic, owner-drop cleanup, and unexpected-resource-exit reporting (some
cases share a test). No elapsed-time performance claim follows from these tests.

The official Windows fixture now uses this library and ResourceOwner rather than
an inline launch loop. It retains valid/wrong capability and REJECT-only mutation
checks. Three isolated runs test ready-front generation preemption, occupied mixed
port refusal, and a fully started real front held behind a test barrier until its
owner token is invalidated. The third must never deliver Ready and must clean up.
All runs require input files gone after completion. They send no proxy payload,
start no WireGuard/Shadowsocks workers, and change no network settings. The mock
agent/desktop remains isolated; no production agent command enables this front.

The fixture owner waits at most40s and its Python parent caps each mode at50s.
This covers startup acceptance<15s, three post-start controller checks up to6s,
the late-start test barrier up to5s, stop up to5s, post-stop check up to2s, plus
scheduling/setup margin. Production readiness and stop limits are unchanged.
Neither fixture budget claims to cancel an indefinitely blocked kernel call.

## Network-bound candidate resources

`start_network_bound` additionally captures fresh Available physical evidence
(hint revision, continuity generation and binding identities). Every owner poll and Ready application
requires that same revision/continuity/identity to remain freshly observed. Interface,
address or route notifications invalidate this guard even when the offline epoch
does not change; periodic binding-identity changes and evidence expiry also
invalidate it. Obsolete candidates are cancelled and their late resources stopped
without declaring an outage or incrementing epoch solely because of Unknown.
The ordinary `start` API used by a front-only resource keeps its existing domain
token contract and does not acquire this extra candidate binding requirement.

Six additional actual-thread resource tests cover required fresh evidence, a
network hint during blocked startup (no Ready and no fabricated outage), and the
ordinary front remaining unaffected by a hint alone, and a binding change in
the same online epoch without a notification. A delayed-owner TTL-gap regression
rejects the old candidate even when the same poll accepts a fresh identical
sample; a positive control preserves candidates across uninterrupted refreshes.
Three observer tests cover
expiry before another poll, changed identity without a notification, and
continuity-counter saturation refusing further bound evidence. This
still does not start a real VPN worker or replace per-endpoint route/source and
socket verification. Cancellation remains cooperative and owner-driven.

Construct route/source snapshots inside the captured network-bound I/O operation,
check cancellation after each bounded read/start phase, and do not feed a cached
snapshot from an earlier operation into a new factory. The owner guard fences
completions against that dispatch evidence; it cannot inspect arbitrary caller
closures or make an old precomputed snapshot belong to a newer operation.

Evidence continuity advances on reset, Unknown/Unavailable, or identity change,
not each successful identical sample. A TTL gap followed by same-poll fresh
evidence cannot restore an old candidate authorization. Counter saturation
permanently refuses bound evidence; ordinary front behavior is unchanged.

## Explicit clean startup cancellation

`start_cancellable` and `start_network_bound_cancellable` admit a typed
`BuildOutcome::CancelledClean`. The factory must return it only after every
partially constructed resource is synchronously cleaned up. The worker also
requires the owner cancellation flag; an unsolicited absent resource is sticky
Start failure. It emits Finished(Ok) without Ready only after the factory returns,
so the slot remains occupied during blocked cleanup. This is a factory contract,
not an ability for the generic owner to inspect arbitrary closure-owned handles.
Existing start APIs still wrap successful resources and preserve sticky failures.
Cleanup uncertainty, Stop failure and worker failure never become clean cancellation.

Three additional actual-thread tests cover blocked partial cleanup and retry on
the same owner, unsolicited clean cancellation rejection, and uncertain cleanup
remaining sticky. Existing late-resource and failed-stop tests are retained.
The official front fixture adds four cancellation checkpoints: before input,
after input/before CreateProcess, after owned process creation, and after complete
readiness validation/before Ready return. A real owner cancels across a bounded
thread barrier; each run requires StartError::Cancelled (not Cleanup), no Ready,
private input gone before retry, and a reusable same-owner slot. The retry is a
Noop resource, not a second real engine start. Existing normal running-front stop,
occupied mixed rejection and late fully-built resource cancellation also run.
Seven modes are individually bounded by the same50s Python deadline.

Front::start_with_checkpoint exposes typed worker-side checkpoints; callbacks
must be bounded. The default start API preserves its original cancellation
callback behavior. StartError::Cancelled after process creation is returned only
after whole-Job termination has succeeded; failure to confirm it is Cleanup.
No test claims cancellation interrupts CreateProcessW itself or an arbitrary
blocked kernel call, and these fixtures do not start VPN workers or alter routes.

`start_on_binding` additionally restricts a selected physical identity to the
current observation and passes an operation-scoped BoundNetwork to the factory.
It detects new notifications on the I/O worker itself and sets the shared cancel
flag, while the owner still checks freshness/continuity before accepting Ready.
Two actual-thread tests cover membership rejection and cancellation detection
before a subsequent owner poll. The engine worker chain is documented in
`../engine-mihomo/WORKER_LIFECYCLE.md`; positive VPN startup is still unverified.

## Read-only cancellation monitor

BoundNetwork can issue a cloneable BoundCancellation view for a library that
owns a callback. It holds only the captured hint revision and shared cancellation
flag, never a binding or a constructor for resource authority. Notifications
remain visible without owner polling, and all clones observe owner cancellation.
Keeping a monitor after dropping the original guard does not authorize another
start or bypass the existing Ready/token/continuity checks. An actual-thread
regression covers both notification and explicit cancellation paths.

## Candidate evidence

The candidate-specific start API binds a registered attempt to the active
resource and supplies a one-shot evidence sender. Payloads are held until Ready,
then checked against the full attempt/token, physical continuity, time and live
resource presence. See CANDIDATE_EVIDENCE.md. This adds no front selection or
persistence, and does not change ordinary front/noncandidate APIs.

## Persistent connection aggregate

`start_persistent` is an explicit opt-in for one I/O-owned aggregate containing
its fixed front and at most one identity-exclusive worker. It can start a REJECT
front while the physical network is offline. Domain generation/attachment/hints
never terminate this aggregate's lifetime; explicit cancel, actual resource failure
and the existing confirmed-stop/drop barrier remain. All existing `start*` entry
points retain their token-bound behavior. Never create substitute owners to evade
sticky cleanup failure.

A persistent aggregate has a separately bounded one-operation registry.
`begin_operation` requires accepted aggregate Ready/presence, fresh Available
binding evidence, a nonzero worker instance and an optional current domain attempt.
It returns a non-serializable OperationTicket and a new BoundNetwork. State/epoch,
physical continuity, hint or deadline invalidation cancels that operation only.
Cancellation keeps the registry occupied until the host has received the matching
I/O cleanup/reconciliation completion and calls `finish_operation`. Tickets compare
retained allocation identity before freeing or cancelling; public IDs may collide
across owners without granting authority. Owner polling remains nonblocking.

This registry does NOT certify a concrete worker's presence, outbound packets,
selector state or policy persistence. The aggregate must independently check its
exact retained worker instance at commit. A stale operation or `is_running=false`
is not evidence that a Job stopped; retain identity exclusivity until confirmed
stop. Selected-worker verification uses a new guard with the same configured
physical binding. It must not refresh/reuse the cancelled startup guard.

Portable tests cover offline aggregate startup, generation/outage/hint/deadline
cancellation without aggregate stop, pending-I/O exclusion after cancellation,
foreign-ticket collision and explicit lifetime cleanup. Real host wiring and
selection/persistence integration have separate acceptance gates.
