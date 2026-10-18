# Physical observation connected to the recovery state owner

ObservedOwner owns one domain State and one physical sampling worker. The worker
never reads or mutates State. All observations and domain tick effects are applied
by the caller's owner thread through nonblocking poll; control commands can still
be handled while an OS sampler is blocked. Construct with a fresh boot's state
and use the same owner for the agent lifetime. The mock agent remains isolated;
this module is not silently wired into its IPC or advertised as a real VPN.

One request and one result mailbox, each capacity1, permit at most one outstanding
sample. Idle periodic dispatch is500ms. A thread-safe ChangeHint only increments
a coalescing sequence, performs no I/O and never claims an outage. A changed hint
invalidates current evidence and any older in-flight result, then requests a new
sample once the existing call actually finishes. The Windows constructor registers
interface, unicast-address and route notifications for both address families, feeding
this same counter. Callbacks ignore incomplete OS-owned rows and never sample or
mutate domain state. Startup registration failure is returned to the caller.
The registration lease lives on the worker, so owner Drop does not synchronously
wait for notification cancellation; successful worker teardown cancels all three.

Results are accepted only before2s from dispatch through owner application,
including queue/scheduler delay, with ordered monotonic timestamps and matching
hint/request identity. Exactly2s is expired. Last positive evidence independently
expires at2s even if a younger new sample remains in flight; stale evidence cannot
complete the domain's2s offline-release settling window. A gap is applied as a
separate Unknown reset before any newly queued Available result on the same poll.
The final Acquire read of the hint counter immediately before owner application
is the batch linearization point: an earlier notification rejects the batch; a
concurrent later notification is consumed on the next poll. Timeout becomes Unknown
and clears physical bindings but retains the in-flight slot. It never starts a
replacement thread or queues another request behind a blocked kernel call.

Confirmed Unavailable goes through State::observe, increments its epoch and
invalidates old recovery tokens. Unknown cannot create an outage or release an
existing offline latch; new Available must again settle continuously under fresh
evidence. Provider attachment/binding inconsistencies become Unknown. Domain
effects are returned to the owner; this slice does not yet execute engine effects,
cancel a candidate Job or perform selector/policy transactions.

A panicked/disconnected worker becomes sticky Unknown and is not auto-replaced.
Dropping the owner does not join a blocked kernel call: channel closure makes the
single worker exit when that call returns. No hard kernel cancellation is claimed.
Do not create replacement owners to work around blocked calls; actual agent exit
ends its process threads. A production restart/lifecycle owner remains responsible
for that boundary and for wiring returned effects to owned engine jobs.

Fourteen portable tests use actual threads/channels plus a shared monotonic test
clock. They cover owner responsiveness during a blocked sample, single-flight
timeout/no replacement, late-result rejection, hint races, confirmed epoch
invalidation, Unknown/offline settling, independent evidence expiry including owner stalls across expiry, strict1999/
2000ms boundaries, abnormal worker exit, nonblocking owner drop and inconsistent
provider evidence, and worker-owned notification-lease teardown after a blocked
call returns. A Windows-only fifteenth test passes an actual read-only platform
sample through this worker; completion may legitimately be Unknown. It does not unplug a NIC, alter routes or validate TUN.

Network-bound resource startup can request a fresh binding-evidence value from
this owner. It includes the hint revision, evidence-continuity generation and full accepted physical binding
identities, and refuses Unknown, empty, expired or not-yet-consumed hint state.
Expiry is checked even before the next periodic owner poll. This value is not a
route/source proof and does not replace EgressSnapshot or actual socket checks.

Continuity advances on reset or non-Available/changed binding observations, not
on uninterrupted identical refreshes. Thus a queued fresh sample cannot hide
a TTL gap from an older bound candidate. Saturation permanently closes only
the bound-evidence gate. The counter saturation is covered by a portable test.
