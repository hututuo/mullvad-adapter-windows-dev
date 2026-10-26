# Native fallback requirements

## WIN-NATIVE-01 Ordered bounded fallback
WHEN all selected-city SS candidates have been exhausted, THEN try a bounded
IPv6 pass followed by IPv4 over the same fixed maximum-five relay set, and only
then enter optional chain. Keep existing time budgets and fixed-chain policy.
Missing official addresses/allowed ports or matching physical family MUST skip
without remote failure history. Do not enable system IPv6 or change OS routes.

## WIN-NATIVE-02 Exact protocol identity
WHEN rebuilding or restoring a recorded path, THEN validate its transport,
relay address and port against current official metadata and preserve its
protocol/socket. Native original short retries are serialized; after failure,
prefer SS on that node before other SS nodes. A saved startup hint unavailable
on the new physical family may use SS. Unknown/withdrawn exact paths MUST fail
explicitly. No native success or failure is an SS rotation entry.

## WIN-NATIVE-03 Ownership and unavailable routes
WHEN local native binding/route is unavailable, THEN skip without a remote
negative after current ownership and cleanup are confirmed. Physical offline,
network-change cancellation, stale evidence and unknown cleanup MUST retain
existing guards. An original native path whose physical family disappeared
MUST leave the original waiting phase and continue its relay SS choices without
a remote negative; trial rollback must preserve its verified rescue. There is
at most one identity peer; front has no DIRECT bypass.

## WIN-NATIVE-04 Observable protocol
WHEN native fallback is selected, THEN home, tray, endpoint details and safe
reports distinguish IPv6, IPv4, SS and chain. Trial-continuation fences include
protocol. Optional added fields keep old snapshots readable. Verify pure ordering,
authorization, restoration, budgets, bookkeeping and Windows-native regression;
real egress, installation and natural recovery remain independent validation.

This change extends WIN-PARITY-04's prior scope; it does not claim multihop/PQ,
QUIC, UDP-over-TCP or seamless handover support.
