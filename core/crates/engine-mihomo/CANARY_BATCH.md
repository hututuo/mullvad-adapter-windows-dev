# Worker-local canary measurements

`Worker::probe(&mut self)` explicitly runs the existing owned DNS and HTTPS
transports on that worker's retained process, bound-network cancellation guard
and immutable mixed listener port. It is not invoked by mock IPC or automatic
startup, does not select a front, and does not publish anything to domain State.
Control-plane startup, measured probe success and actual WAN socket binding
remain separate evidence. No live third-party request is part of the test suite.

IP HTTPS and inner DNS start on separate scoped threads. Hostname HTTPS starts
only after positive inner DNS and can overlap an unfinished IP probe. Failed DNS
skips hostname while preserving IP evidence for the existing degraded-DNS policy.
Optional ping/controller diagnostics are not readiness inputs and are not added.
The existing pure domain Canary matrix is reused: alive = IP or hostname HTTPS;
Ready = alive and DNS and hostname HTTPS. IP failure alone does not defeat Ready
when DNS and hostname succeed. No extra all-three-success requirement is added.

Each result keeps its own monotonic completion time. `fresh_canary(now)` rejects
future or older-than-five-second observations individually, never replacing an
older DNS/IP timestamp with the later batch completion timestamp. Exactly five
seconds remains valid, matching the existing domain TTL. Slow otherwise healthy
batches can therefore need new evidence; stale is not a measured relay failure.
Raw Report is not an operation/path/attempt token. The explicit candidate mailbox integration associates captured operation identity
through the control owner (see CANDIDATE_EVIDENCE.md). The host must still validate current
boot/generation/epoch/operation/path/front/attempt, and convert the monotonic
clock consistently before using any result in a domain transition. Report implements MeasuredEvidence using its oldest phase. This does not
prove host metadata mapping or the final front/persistence transaction.

All scoped threads are joined before returning any result, including panic,
spawn failure and cancellation. Local panic/spawn failure is LocalFailure;
cancellation cannot be converted into negative relay measurements. A failed
process/TCP ownership proof sets a shared rejection flag, cancels sibling I/O and
returns LocalFailure, even if another probe reports success. A retained process
liveness check and final network-hint cancellation check follow collection.
The duplicate handle and sockets remain owned until the joined operation ends.

Individual DNS/IP/hostname acceptance budgets remain two/eight/twelve seconds,
with their existing bounded body/frame limits and cancellation slices. Kernel
calls still cannot be forcibly interrupted, so joining is a cleanup guarantee,
not a hard OS-thread completion deadline. No detached sibling may outlive a
returned batch. No process is terminated here; the ResourceOwner still owns its
normal cancellation and stop lifecycle.

Twelve portable tests use real threads and bounded synchronization to check
IP/DNS overlap, DNS-before-hostname ordering, DNS skip and degraded classification,
IP-failed Ready matrix, cancellation with both probes blocked until release,
local panic classification (including hostname with IP still active), all DNS
dependency refusals, cancellation-before-start/status, every phase at five seconds/
plus one nanosecond/future timestamps, and all feasible matrix/time-order cases.
They use injected probe functions; transport byte-level tests remain in the DNS
and HTTPS modules. Windows API checking covers production composition signatures.
A positive full batch over an actual WG/SS worker, final front/persistence
transaction, spawn-failure injection and actual user/network acceptance are not
covered here. Candidate mailbox tests are separate portable control tests.

`Report` also implements the typed `ReadinessEvidence` interface for the owner
selection preflight. It rechecks all phase timestamps with the real monotonic
clock. A fresh mailbox stamp never refreshes an old phase. The owner independently
fences operation/candidate/resource/network continuity on each check. This seam
does not enable a production agent, switch the front, or certify actual egress.
