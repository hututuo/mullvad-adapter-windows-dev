# Design

- Catalogue owns validated, canonical public comparison facts. The catalogue I/O
  worker computes a bounded typed report against the previous effective data.
  Dashboard/IPC only publish that report; status reads never fetch or diff.
- The current relay is captured when a job starts. Detail UI identifies that
  relay and warns if the user has subsequently switched. Shared SS/WG port
  changes are included. First fetch records a baseline rather than all-added.
- API and cache outcomes are separate. Failed cache replacement preserves old
  disk bytes while valid new data remains usable in memory.
- InletTrials separates this round's spent budget from persistent tried tuples.
  Reconciliation prunes withdrawn tuples without refunding the current round.
  Peer-key change starts a new peer window. Direct and chain tuples are separate.
  Bounded windows/scores share the existing DPAPI RecoveryHistory record; old
  score-array payloads migrate. Disk saving is serialized outside connection and
  status locks and coalesces to the newest complete snapshot.
- Full public diffs remain in local bounded logs. Shared diagnostics project
  only counts, safe state and changed-field keys; raw differences are removed.
- Worker-only TLS SNI recovery matches the Mac scope, retains inner WG DNS and
  excludes private destinations. Both ordinary and chained dual-stack WG use
  MTU 1280. The fixed engine version and fail-closed front remain unchanged.

Persistence is bounded to 32 recent relay/route windows and 1024 tried tuples,
plus bounded scores, below the encrypted-record size limit. These are client
retention policies, not official relay capabilities. Windows retains its
authorized dedicated UDP/443 alternative in addition to both catalogue forms.
