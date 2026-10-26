# Design

`live_route` maps a stable recorded protocol plus socket to an authorized engine
transport. SS uses current dedicated/primary SS authorization. Native routes
must match the relay's current address and an advertised WG port. The preferred
V6/33431 and V4/51820 ports are local defaults, re-authorized against metadata;
no server address is embedded in product code. IPv6 scope/flow identifiers are
not accepted. Physical binding selection follows the outer endpoint family.

The fixed round relay set passes through SS, native V6, native V4, then optional
chain. New phases refill only the existing candidate queue; they retain its
monotonic deadline, attempt count, city, exact-relay intent and spent SS window.
Missing address/family/port skips that candidate without negative evidence.
A native fallback worker with no route may advance only after confirmed cleanup
and current settled ownership; it never consumes SS history. Cancellations,
local probe failures and stale evidence retain existing retry/cleanup guards.

Startup, exact original rebuild and trial rollback validate recorded transport.
A saved native startup hint with no matching local family may revert to SS;
an exact active rebuild/rollback cannot silently change protocol. Failure of a
native original after its short retries enters its relay's SS choices before
other SS relays. Successful native paths are persisted in existing selected-path
storage, never mixed into SS rotation. Retry identity includes protocol even
when sockets coincide. Chain return keeps its existing bounded serial SS trial
and restores the previous chain on failure; backup-test rollback can restore a
previous native path. Native families never add a second concurrent peer.

Wire snapshots add optional validated transport fields for backward-compatible
reads. Home shows a fifth recovery step for native fallback, actual protocol and
endpoint; tray and shared reports expose only allowlisted protocol names. Source,
Windows tests and target-machine egress/long-term recovery remain separate gates.
