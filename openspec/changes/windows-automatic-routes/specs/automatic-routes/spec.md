# Requirements

## AR1: Anonymous catalogue refresh does not block recovery
- WHEN the physical network has settled after application startup, THEN refresh
  official relays even with a cache, retain that cache on failure and retry at
  1/5/15-minute capped delays. After success wait 24 hours.
- WHEN account or tunnel work is active, THEN the HTTP refresh lane may continue
  without acquiring its operation/peer gate or cancelling a healthy connection.
- WHEN network hints repeatedly flap during failure, THEN at most one physical
  recovery wake bypasses backoff until a successful refresh.
- WHEN legacy cache time is unknown or future, THEN do not display it as a
  verified recent fetch. Never call an active metadata flag a successful tunnel.

## AR2: Startup retains intent and protection
- WHEN startup connection is enabled and identity/city/catalogue are configured,
  THEN connect once after physical settling, prioritizing a still-authorized last
  node/inlet, with full current readiness before front selection.
- WHEN the user disconnects/cancels before startup dispatch, THEN cancel that
  intent; it must not race accepted settings/account/device work or ICMP cleanup.
- WHEN the front has no healthy worker, THEN reject rather than fall back DIRECT.

## AR3: Optional independent chained carrier
- WHEN a user imports a compatible SS leaf from real local Clash configuration,
  THEN validate its immutable preview digest, store credentials only in DPAPI and
  return only public summaries to the renderer.
- WHEN a fresh direct attempt is dead and cleanup is confirmed in automatic mode,
  THEN try the same authorized Mullvad SS inlet through the configured independent
  leaf before advancing bounded same-city choices. Count both routes together.
- WHEN the original committed path is chained, THEN rebuild that same route first;
  reject replacing its upstream until explicit disconnect. Do not periodically
  bounce a healthy chain back to direct or start a second live WG peer.
- WHEN chain mode is forced without valid local configuration or public physical
  destination proof, THEN fail explicitly. Final OUT contains only Mullvad.

## AR4: Honest daily traffic boundary
- WHEN the adapter opens, THEN do not silently alter system proxy/TUN or Clash
  groups. Explain that the selected external Clash configuration owns ingress.
- WHEN either route is selected, THEN show the actual attempted/committed route,
  and distinguish build, candidate, install and real egress evidence.
- WHEN Clash Verge switches between sidecar-release and production service mode,
  THEN resolve only its strict current-user SID hash pipe pair before the control
  transaction; require one present endpoint and freeze that name. Ambiguity,
  foreign owner or access errors fail closed without HTTP fallback or secret.

## AR5: Exhaustion is followed by bounded cooldown rounds
- WHEN an authorized connection intent exhausts a round and automatic recovery is
  enabled, THEN retain its city and explicit relay and schedule a new round after
  60/180/300 seconds capped, without refilling the running round on host ticks.
- WHEN the physical network is offline or unsettled, THEN do not dispatch a new
  round. Transient local setup failures may schedule a cooldown without consuming
  an inlet; uncertain cleanup or invalid protection/identity must not auto-loop.
- WHEN a fresh connection succeeds or the user disconnects, THEN cancel pending
  cooldown. Disconnect also revokes the retained intent. Show a countdown and
  allow stopping or explicit immediate retry.
