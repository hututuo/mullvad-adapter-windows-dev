# Pure public relay catalogue

This parser does no fetch, account login, identity association, DNS, ICMP,
filesystem cache update or engine start. Metadata capabilities are not liveness,
readiness, authoritative current withdrawal or fresh network evidence. A future
owner must bind requests to generation, validate HTTPS/route, timestamp responses
and publish snapshots transactionally. No live response is an acceptance fixture.

Limits:8MiB body,8192 rows,256 ranges per transport,32 extra SS IPs per row, plus
serde_json's recursion bound. Errors are fixed categories, never body echoes.
Bad rows are counted/filtered; no valid rows fails the snapshot. Both WG and SS
range arrays are required; ordered integer ports must be within1..65535. Names
are reserved before other row validation, preserving Ruby's first-occurrence
rule even when that first occurrence is malformed. Later duplicates cannot
replace it. Inactive rows remain represented but offer no transports.

City selection is exact location equality. Auto capability order remains SS,
IPv6, IPv4; direct families need their address and advertised33431/51820 port.
SS requires IPv4 and nonempty valid SS ranges. This does not rank extra endpoints,
choose SS ports, infer health or reserve peers. Address syntax can include local
or reserved fixture IPs; engine endpoint/route policy remains a separate gate.

Nine sanitized cases run against both Rust and the existing Ruby validator:
valid/invalid mixtures, inactive, duplicate including invalid first occurrence,
IPv6-only, zero port, missing SS ranges and non-boolean active. Four Rust tests
also cover limits, port edges, exact city selection and stricter schema deltas.
The Ruby1/19 comparison runs in the existing macOS compatibility test glob.
Its transport comparison explicitly wraps available_transport_modes with an
active check, modeling the active relay view; that legacy function by itself
still returns advertised modes for inactive rows. The corpus compares validator
results plus this wrapper, not equivalence of the two unwrapped native functions.

Intentional Windows hardening, not claimed as identical legacy behavior:
- canonical nonzero32-byte base64 public keys, replacing merely nonempty keys;
- typed IPv4/IPv6 fields, not arbitrary IPAddr families or CIDR strings;
- JSON integer ports, not numeric string coercion;
- bounded ASCII identifiers and trimmed normalized strings;
- exact city metadata instead of hostname-substring fallback.

These checks do not prove account/public-key association or relay reachability.
Display names/provider details, endpoint history, refresh/cache fallback,
network-bound HTTPS and account APIs remain outside this slice. The source
contract is daemon/mullvad_adapter.rb's metadata validator; only synthetic data
is saved and no old daemon production behavior is changed by this crate.
