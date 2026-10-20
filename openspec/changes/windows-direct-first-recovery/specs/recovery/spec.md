# Recovery requirements

## DF-01 Preserve before rebuilding
WHEN a current owned worker has its first fresh real data failure, THEN keep it,
recheck after approximately two seconds, and require a second consecutive current
failure before rebuilding. Success clears the streak. Stale, cancelled, local or
binding-invalid measurements cannot supply the second failure. A physically
missing worker may begin recovery without waiting for an impossible recheck.
WHEN IP/service data remains alive but DNS alone fails, THEN preserve the worker.
WHEN the backend is healthy and the local front selector/process fails, THEN
repair the local entry before changing the WG relay or SS inlet.

## DF-02 Ordered and bounded direct recovery
WHEN a current original SS path has failed and cleanup is confirmed, THEN allow
three serial starts of that exact inlet (first immediately, then at least one and
five seconds after the preceding failed attempt has cleaned up), followed by at
most two other authorized inlets on that relay. Use measured success history for
ranking; history is never current readiness or metadata authorization.
THEN try at most four other relays in the selected city, at most two direct inlets
each. Direct and chain use one immutable, bounded relay set for that round.
No new attempt starts beyond the 300-second round budget. An in-flight attempt
has its existing 90-second hard ceiling plus confirmed-cleanup time. These are
ceilings, not a promise of recovery latency. Local/stale retries and
metadata refresh cannot renew the round or manufacture endpoint failures.

## DF-03 Chain last and serial return
WHEN the authorized direct queue has actually exhausted, THEN Auto may use a
saved independent SS node as the final chain phase. Elapsed time alone does not
authorize skipping direct paths. Each relay has at most two chain inlets.
WHEN Auto is connected through chain, THEN schedule a serial direct trial after
120 seconds; failures restore the exact prior chain and back off 5/15/30 minutes.
WHEN a new chain is promoted after a natural recovery and the previous direct
trial deadline has already elapsed, THEN renew that deadline from this promotion
using the current backoff. Preserve both the failure count and any still-future
deadline; do not immediately interrupt the newly restored chain for an old timer.
Never have two WG tunnels using the same identity. Forced Chain mode is retained.
Manual disconnect cancels pending recovery and direct-return intent.

## DF-04 Automatic preparation and one test
Read compatible SS leaves from actual local Clash configuration/provider cache;
use US, Singapore and UK name hints only for preference, then verify real UDP
exchanges with physically bound sockets. No WG identity or external selector
mutation is used for background qualification. Preserve saved credentials if no
candidate succeeds or cleanup is uncertain. Secrets remain native RAM/DPAPI.
One Test Backup Route action prepares a node, verifies a complete owned Mullvad
chain with IP/DNS/HTTPS, then restores the previously active route. The UI does
not require per-node test levels or claim full-chain success from SS UDP alone.
A persisted explicit node preference takes precedence over automatic ranking.

## DF-05 Useful main-page control
Expose current phase, actual target relay/inlet, attempts, elapsed/start budget,
wait and next action on the city page. Offer retry-current, a new same-city round,
chain fallback, direct return and stop. In-flight/preempted attempts cannot be
silently replaced. Fixed-height feedback must avoid banner-driven layout jumps.
Fresh failure logs must not reuse a previous successful batch's detailed probe
outcomes. Only details from the same measurement may accompany its canary values;
manual preemption of background maintenance must remain an exportable event.

### Requirement: automatic backup qualification does not starve later regions

The native SS-only qualification pass SHALL admit at most two compatible leaves
per preference class (US, Singapore, UK, other), at most eight leaves total. Each
admitted leaf SHALL receive its own 12-second data/start deadline and confirmed
cleanup; a failed prefix SHALL NOT consume a shorter shared deadline that prevents
later admitted regions from ever being checked. Cleanup uncertainty SHALL stop
the pass. This pass SHALL NOT acquire a WG identity lease or interrupt the active
WG tunnel. On replacing the saved chain configuration, prior full-test status
SHALL be cleared rather than attributed to the new configuration.

#### Scenario: unavailable US and Singapore leaves precede a working UK leaf

- WHEN the earlier admitted US and Singapore leaves time out
- THEN the same pass still attempts its admitted UK leaves
- AND a new pass does not repeatedly omit those leaves due to a shared 45s cap.
