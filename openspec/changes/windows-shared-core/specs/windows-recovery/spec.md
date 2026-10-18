# Windows recovery requirements

Status: PROPOSED. Derived from reviewed macOS source behavior, not Windows runtime evidence.

## ADDED Requirements

### Requirement: WR-01 Physical attachment evidence

The platform observer SHALL emit available/unavailable/unknown from bounded physical-interface and address observations independent of VPN interfaces, proxy selection, DNS and test websites. The control core SHALL pause automatic recovery only on confirmed local attachment unavailability; unknown SHALL neither create an outage nor release an existing outage latch.

#### Scenario: Virtual interface remains online after Wi-Fi disconnects
- **WHEN** all physical interfaces lack usable attachment/address while a TUN/virtual interface still has an address
- **THEN** the backend enters waiting_network, preserves city/path and stops new automatic recovery/probe attempts; it does not add failed relay/SS histories or a DIRECT route.

#### Scenario: Another physical interface remains usable
- **WHEN** Wi-Fi disconnects but Ethernet remains attached with usable IPv4 or IPv6
- **THEN** the backend does not infer total local outage and lets normal data-path health policy assess connectivity.

#### Scenario: Observer error and router WAN failure
- **WHEN** OS evidence cannot be read or only an Internet/DNS probe fails
- **THEN** the backend reports unknown or the specific upstream failure; that fact alone cannot assert physical attachment loss.

### Requirement: WR-02 Original path first after attachment returns

After continuous positive attachment evidence for the configured settle interval (baseline two seconds), recovery SHALL verify the existing worker first. A live data path SHALL be preserved even when DNS/service readiness is degraded. If not alive, recovery SHALL rebuild the original relay/mode/SS inlet and multihop entry where applicable before same-city alternatives. Local construction or slot contention SHALL NOT count as relay data failure.

#### Scenario: Original data plane remains alive
- **WHEN** stable attachment returns, data canary succeeds and DNS fails
- **THEN** the same worker is preserved, recovery reports degraded_dns and subsequent normal DNS/service policy continues; recovery does not switch IP solely for this test failure.

#### Scenario: Original path fails or its relay has been withdrawn
- **WHEN** the original data path and exact-path rebuild are confirmed unsuccessful, or the original relay is no longer valid in metadata
- **THEN** only bounded candidates in the selected city may be attempted; no valid same-city candidate leaves the connection disconnected with a reason rather than moving to another city.

#### Scenario: Slot is busy or local engine cannot start
- **WHEN** original-path construction is blocked locally without confirmed relay canary failure
- **THEN** recovery defers with a local-component reason and bounded backoff, without quarantining the relay or starting unrelated candidates.

### Requirement: WR-03 Attempt ownership, cancellation and bounded concurrency

Lifecycle state SHALL have one authoritative owner. Blocking probes/process waits SHALL occur outside its commit section and have time/output/concurrency bounds. Completions SHALL validate boot/generation/network epoch/operation/worker/front ownership before changing state or history. Baseline retry budgets, evidence TTLs and peer exclusivity SHALL remain explicit and tested.

#### Scenario: Late probe after outage or manual selection
- **WHEN** a probe completes after network epoch changes, a worker is replaced, or a new user operation supersedes recovery
- **THEN** stale evidence cannot select a worker, overwrite the user selection, release newer recovery, or record a false node failure.

#### Scenario: Busy commit and repeated wakeups
- **WHEN** a valid health observation waits for commit or multiple failures wake the loop
- **THEN** the loop reuses bounded-age evidence and merges duplicate wakeups; it does not repeat full probes only because of lock contention or queue unbounded attempts.

#### Scenario: Same WG peer reconnect
- **WHEN** reconnect or PQ final construction targets an already owned WG peer
- **THEN** ownership remains exclusive throughout bootstrap/negotiation/final construction; cleanup is bounded, and no second independent live instance with the same identity/peer is created.

### Requirement: WR-04 Scoped low-cost candidate maintenance

Fast checks SHALL use daemon-derived ICMP targets and transport/interface semantics, bounded concurrency within a city and sequential city scopes. Routine maintenance SHALL observe a small ranked set rather than fully testing all nodes or preparing unverified same-peer hot standby. ICMP results SHALL be distinct from complete tunnel readiness and must not quarantine a node.

#### Scenario: Ping does not answer
- **WHEN** a candidate fails ICMP without a current complete transport canary
- **THEN** its fast-check evidence is timeout/unknown as appropriate; it is not represented as a proven unusable or ready tunnel.

#### Scenario: Candidate selected for actual use
- **WHEN** a new fallback path is prepared while local attachment is available
- **THEN** its complete IP/DNS/HTTPS and required protection validation finishes before front selection; an expired historical result or ping success cannot substitute.

### Requirement: WR-05 Bounded and attributable diagnostic evidence

Backend events SHALL identify layer, monotonic duration, wall time, operation/attempt/recovery context and outcome without secrets. Event retention SHALL use the existing two-file decimal 20MB capacity budget rather than promise a fixed number of days. Export SHALL combine sanitized state and bounded log tails into an owner-readable local file and allow path copying without automatic upload.

#### Scenario: Interruption and later recovery
- **WHEN** attachment, worker, front, DNS or service evidence changes across an interruption
- **THEN** reports permit the reader to correlate observation, deferral, rebuild/commit and outcome; missing evidence remains explicit and is not inferred from a single successful website.

#### Scenario: Offline report and log rotation
- **WHEN** the user exports while paused or logs exceed the capacity cap
- **THEN** offline diagnosis skips external probes, export includes actual retention window/tail limits and status, rotates bounded events, and excludes credentials, keys, capability values and secret helper output.

### Requirement: WR-06 Explicit data and bootstrap routing

The Windows engine integration SHALL preserve a verified external-ingress/adapter egress boundary. Relay/SS sockets, metadata/account bootstrap and in-tunnel canaries SHALL each have an explicit route policy; they SHALL NOT recursively re-enter the adapter through the external Clash TUN. The front SHALL select only owned validated workers, with no DIRECT fallback.

#### Scenario: External Clash captures the default route
- **WHEN** external Clash TUN is active and the adapter creates a relay/SS socket
- **THEN** the socket uses a verified physical-egress binding or configured safe exclusion; failed binding reports a local integration error rather than repeatedly reconnecting the relay through itself.

#### Scenario: Bootstrap proxy becomes unavailable
- **WHEN** metadata/account bootstrap cannot use its configured route while the active tunnel remains healthy
- **THEN** control-plane failure is recorded separately, validated cached metadata may be used under its policy, and no secret request is silently sent by an unintended fallback route or healthy worker replaced solely for that bootstrap failure.
