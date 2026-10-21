# Requirements

- SR-1: WHEN a read is cancelled, THEN retain prior state without increasing failures. WHEN an older result finishes after a newer observation, THEN discard it.
- SR-2: WHEN a single transport read fails, THEN show pending state with last-success age. WHEN three consecutive transport failures span ten seconds, THEN show unavailable local status, never claim the tunnel is down. HTTP and decode errors must have distinct labels and cannot supply transport strikes.
- SR-3: WHEN a fresh read succeeds, THEN clear stale warnings and record recovery. Every status-read entry point must use the same completion fence.
- SR-4: WHEN state reading fails, THEN record allowlisted timing/category/code and subsequent recovery in bounded private files. Include them in diagnostic export, even when the daemon is unreachable. Disk failure or hostile symlinks must not alter unrelated files or stop polling.
- SR-5: UI-only installation must retain daemon/front/worker/Clash process identity and real egress. Never interrupt physical networking or start another WireGuard peer to test this change.
