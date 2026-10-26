# Windows parity requirements

## WIN-PARITY-01 Catalogue explanation

WHEN a valid official catalogue is fetched, THEN compare accepted public facts
against the previous effective catalogue, ignoring map/relay/SS set order and
equivalent address spelling. Publish added/removed/modified counts and bounded
field details, with the check-time relay prioritized. Redact relay public keys
to fingerprints. First fetch has unknown change and a new baseline. A failed
fetch retains prior data/report with an error; disk failure alone does not turn
valid API data into a fetch failure. Refresh remains one-in-flight and uses the
shared six-hour schedule and bounded 30-to-300-second failure backoff.

## WIN-PARITY-02 Small windows over the complete pool

WHEN SS alternatives are required, THEN derive them from dedicated addresses
and primary-address official SS ports, deduplicate by endpoint, and use a small
per-round window. Preserve the original exact path's immediate/1s/5s retries;
then at most three original-relay alternatives and four same-city relays with
two each. Chain remains a separate final phase, with existing return policy.
No background full-WG sweep or competing same-identity peer is introduced.

## WIN-PARITY-03 Persistent rotation

WHEN a fresh, owned attempt is confirmed failed and cleaned, or committed as
healthy, THEN remember that tuple in its relay/route window. Planning, local
failure and cancellation do not consume it. Prioritize unseen tuples until the
authorized pool is exhausted; only then reopen the cycle. Restart/identical
refresh preserve the window. Partial pool changes retain common tuples, while
peer-key change invalidates the old peer window. Neither pool nor key changes
refund this round's budget. Migrate old score-only records without touching
identity/account storage, and surface asynchronous persistence errors.

## WIN-PARITY-04 Transport and target safety

SS inner WG target remains the remote loopback 127.0.0.1:51820. The actual outer
SS carrier remains bound to an observed physical IPv4 interface; missing binding
is a local condition, not a relay failure. Dual-stack WG MTU is at least1280.
Only worker public-IP TLS443/8443 may recover visible ClientHello SNI and resolve
through its existing inner DNS. No TLS decryption, DIRECT bypass, new system DNS
listener or forced native IPv6 retry is added. Unimplemented live transports and
required protections retain explicit gates.

## WIN-PARITY-05 UI and evidence

Home exposes update and detail buttons with full clickable areas. A fixed-height
scrollable dialog shows actual changes or explicitly says unchanged; selecting
a later relay cannot relabel the old comparison. Local bounded logs retain full
public diffs. Shared diagnostic status exposes only a safe change summary and
recent shared events omit raw differences. Core tests, Windows-native tests,
synthetic UI, package and real installed egress are distinct acceptance tiers.
