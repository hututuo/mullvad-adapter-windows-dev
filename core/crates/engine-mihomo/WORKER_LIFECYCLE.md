# Bound candidate worker startup chain (not VPN acceptance)

ResourceOwner::start_on_binding issues a non-cloneable BoundNetwork only for a
freshly observed selected PhysicalBinding. It retains the observation hint
revision and shared cancellation flag. A worker checkpoint detects a changed
hint without waiting for another owner poll and sets that cancellation flag;
owner continuity/token/freshness checks still fence Ready. Interface selection
cannot use an identity absent from the current observation. This does not let a
worker mutate domain State or manufacture an offline epoch.

Worker::start takes that operation guard and borrowed identity/listener/transport
inputs. There is no caller-supplied alias or cached EgressSnapshot. On the I/O
worker it reads a new constrained route/source snapshot, derives the alias from
that snapshot, invokes worker_with_route, writes bounded private stdin, checks
freshness/cancellation again, and creates the owned Job process with sanitized
environment. A nonblocking preflight rechecks cancellation, acceptance budget
and route TTL under SPAWN_LOCK immediately before CreateProcess, so time spent
queued for another launcher cannot authorize stale creation. A locally recorded
preflight error distinguishes this no-process refusal from OS spawn failure;
once CreateProcess has begun, cancellation is handled after return by confirmed
Job cleanup. Official executable verification and trusted runtime ancestors
remain caller prerequisites. No mock-agent IPC command invokes this function.

Control-plane startup requires the pinned version, a Selector OUT containing
only MULLVAD selected as MULLVAD, and a connected mixed TCP socket proved owned
by the retained process handle. It does not mutate a front selector or send proxy
payload. Before returning, it collects a second independent route snapshot and
requires identical interface/alias/source/destination and full route fingerprint
(prefix, next hop/scope, metric, loopback/lifetime-safe fields). The second
snapshot must be fresh; the original may age during startup but its fingerprint
must still match. Route reads and every bounded controller phase are followed by
cancellation and15s acceptance checks. Kernel calls are not forcibly interrupted.

Every error after process creation attempts confirmed whole-Job termination with
a5s limit. Cleanup uncertainty maps to sticky Stop failure; ordinary startup
errors are conservatively sticky Start failure. Only Cancelled after confirmed
cleanup maps to CancelledClean. A successful Worker remains worker-owned and
implements liveness/stop; notification cancellation follows the ordinary clean
stop path, not a fabricated health failure. An engine process/graph being ready
is not a ready VPN path: canaries, actual endpoint socket/egress proof, and domain
candidate acceptance are mandatory before any front publication.

Portable tests cover binding membership, notification-driven cancellation before
another owner poll, route fingerprint differences, and exact worker graph
validation with real loopback HTTP fixtures. A Windows actual-thread platform test also covers gate-queued cancellation and
deadline expiry, gate release and input cleanup. Two Windows-only factory negative tests use
explicitly synthetic observation evidence to prove a cancelled operation or a
rejected loopback route returns before private input/process creation. They do
not prove positive physical-WAN selection. The existing official front-only
seven-mode fixture is unchanged by this slice.

Positive real worker startup, real second engine start after cancellation,
WG/SS handshakes, actual socket binding, external-Clash loop avoidance, account
association, DNS/website/IP canaries and live route changes are NOT_RUN. The
factory is code-level integration with negative native gates, not a user-facing
VPN command or a migration-complete claim. Do not infer those properties from
route metadata, a successful controller response, or front-only CI.

## Explicit measurements

The worker retains its mixed listener port and exposes a synchronous `probe`
method for its owning I/O thread. This composes the owned transports into the
joined, per-phase-timestamped measurements described in CANARY_BATCH.md. It does
not alter startup Ready, check(), stop(), front selection or domain publication.
The caller still needs a fenced operation/path/attempt result channel before
using those measurements to accept a candidate.

`build_candidate` composes startup, joined measurement and one-shot publication
for `ResourceOwner::start_candidate_on_binding`. It rejects a sender from another
BoundNetwork operation before launch. Collection/publication rejection stops and
drops the worker before returning; stop uncertainty stays Failure::Stop. A sent
Report is still subject to accepted-Ready, current-attempt and freshness checks on
the owner. It does not mean the host metadata mapping, front switch or disk commit
has been implemented or accepted. No mock IPC calls this library factory.

## Selected-worker operation scope

Persistent aggregates use `is_running` to query only retained process liveness
and `probe_on` with a newly issued operation guard. The configured physical
binding must match the new guard. Startup cancellation never authorizes a fresh
probe and is not the selected worker's lifetime. Legacy `probe`/Resource behavior
remains for earlier token-bound fixtures. `stop_confirmed` uses the existing
whole-Job termination barrier; false liveness alone must not release identity.
Neither API proves actual outer UDP packet transit or grants selector authority.

## Isolated acceptance diagnostics

The Windows maintenance CLI supports `--verify-tunnel --relay <metadata hostname>
--transport ipv4|ipv6|ss` and optional `--port <u16>`. An explicit port must be
nonzero and advertised by the parsed official catalogue for that transport.
This permits testing a published alternate WG port on the same relay without
switching cities or scanning the full catalogue. It never selects a front.

Reports retain closed IP/DNS/hostname probe outcomes, including DNS timeout vs
unavailable and hostname **not run because DNS failed**. A failed dependency is
not misreported as a failed HTTPS request. Worker startup reports its closed
route/config/peer/controller/deadline/start stage; a startup failure is not
automatically labelled uncertain cleanup. Actual cleanup uncertainty still
remains a hard failure. No engine text, private configuration, payload, account
or private key is exposed in these reports, and readiness rules are unchanged.
