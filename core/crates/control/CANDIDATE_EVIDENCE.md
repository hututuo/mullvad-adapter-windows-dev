# Candidate evidence mailbox

`ResourceOwner::start_candidate_on_binding` accepts only a CandidateAttempt that
is still registered in its State, in a candidate stage and before its hard
deadline. Normal physical-binding membership, single-resource ownership and
offline-latch gates still apply. The factory receives the operation's BoundNetwork
and a non-Clone CandidateSender; the receiver stays with the state owner. The
candidate attempt becomes part of active-resource validity, so registering a
replacement attempt cancels the old resource even when the ordinary token and
online epoch have not changed. Noncandidate/front APIs keep their prior gates.

The sender consumes itself on publication into a capacity-one channel. Its
attempt and resource id are private fields fixed by the owner, not supplied with
the payload. `accepts_network` compares the unique shared cancellation allocation
and captured revision, preventing an engine factory from attaching another bound
operation to this sender. A MeasuredEvidence payload supplies its oldest phase
Instant; immutable engine Report implements this trait. The same monotonic owner
clock is read before age measurement. Age is rounded upward to milliseconds and
subtracted without saturation: future/pre-clock-origin evidence is rejected, not
clamped into fresh evidence. Cancellation is checked before and after stamping.

A queued payload cannot be taken until the matching resource's Ready event has
been accepted by the owner. Receipt rechecks resource id, full registered attempt,
boot/generation/network epoch/operation/slot/instance/front, captured physical
binding continuity/revision, cancellation, five-second evidence TTL and attempt
hard deadline. A shared presence flag is cleared before stop and by RAII during
unwind, closing the interval where Finished is still queued but the resource is
already stopping or gone. The payload is consumed or discarded once. Reading an
old mailbox never cancels an unrelated replacement resource.

CandidateEvidence is a result valid at receipt, not a commit capability. Before
any later selection/persistence transaction, the owner must call
`candidate_evidence_is_current` again and apply the domain's existing final
identity/time checks. A later callback, resource death or attempt replacement can
invalidate a previously returned value. The final presence/hint reads provide an
acceptance point; they do not promise the process/network can never change after
that point. No I/O thread mutates State, selects a front or persists a policy.

`Worker::build_candidate` is an explicit library factory. It verifies that the
sender belongs to the supplied BoundNetwork, uses existing worker startup,
collects joined probes, submits the immutable Report once, and retains the worker.
If collection/publication/cancellation rejects, it synchronously stops and drops
the worker before reporting clean cancellation or a local failure. Failed stop
remains sticky Failure::Stop. Negative but structurally valid measurements can be
reported without automatically selecting or committing the candidate. Metadata
mapping from a CandidateAttempt to the supplied WorkerRequest remains the trusted
host's responsibility; no frontend or mock IPC enables this factory.

Sixteen new portable tests include real-thread queued-before-Ready, full-token
changes, replacement attempts, late physical hints, notification during stamping,
old phases, future/pre-origin clocks, failed build, stopped-before-Finished,
unrelated replacement and cross-operation network/sender mismatch. Two of these
are pure exact rounding/future boundary checks. Existing bound continuity-gap,
cancel-cleanup and lifecycle tests continue to run. Production Windows composition
is signature-checked by windows-api-check. No positive full WG/SS candidate,
front-switch/persistence transaction, live WAN socket-binding proof or installed
application acceptance is claimed by these tests.

## Cross-owner operation identity

Local resource IDs, boot strings and complete candidate tokens can coincide in
separate owner instances. They are not a process-wide operation identity. Each
sender message, receiver and accepted evidence therefore retains the exact
resource cancellation allocation as a private operation identity. Arc identity
is checked before mailbox consumption, evidence revalidation, or error-path
cancellation. The retained allocation cannot be reused while any receipt exists.
A foreign receiver returns Stale without draining/closing that receiver or
cancelling either resource; an owner with no active resource also leaves it
untouched. Numeric IDs remain diagnostics and same-owner sequencing only.

Three actual-thread regression tests use separate production monotonic clocks
and colliding local resource IDs: foreign receipt is rejected while rightful
receipt still succeeds; taken evidence cannot be revalidated by another owner;
and a stale receiver cannot cancel a colliding resource in a different owner.
They also exercise receiver/evidence/owner drop and explicit cancellation without
affecting the other resource. These are synthetic resource tests, not native
Windows or real VPN acceptance.

## Selection preflight

`ResourceOwner::check_candidate_for_selection` is a read-only gate for a new
standard single-hop candidate. It requires retained operation ownership, a live
resource, the registered attempt and current network binding, the original
observation TTL, and a typed fresh full canary. `Report` implements that typed
interface using its existing per-phase timestamps. Controller startup Ready or
ICMP cannot substitute. DNS/service degradation rejects a new selection without
stopping or mutating the original path; the existing-path preservation policy
remains separate. IP failure with successful DNS and hostname HTTPS still follows
the shared readiness matrix.

Plain canary evidence cannot certify PQ negotiation or an owned multihop graph,
so these profiles and candidate graphs carrying an entry relay are explicitly rejected until their Windows transactions are
implemented. Success is preflight only: there is no front selection, persistent
policy commit or IPC integration here. Repeat this check at the future final
transaction boundary; never store its `Ok(())` as reusable authorization.
