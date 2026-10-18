# Public history summary contract

This is an isolated, read-only data/display library. It parses caller-provided
synthetic or already normalized public summary arrays and computes the existing
history statistics. It performs no file access, migration, writes, network I/O,
clock reads, engine actions or control/IPC publication. No production caller is
connected by this slice. All shared fixtures are synthetic.

## Source and meaning

The field contract is `daemon/mullvad_adapter.rb`'s `relay_history_snapshot` and
`ui/Sources/MullvadAdapterUI/Models.swift`'s `RelayHistorySummary`. The former
removes the private `last_result`, recomputes `readiness_rate`, and sorts by
relay then transport. A row is identified by **relay + concrete transport**;
`ss`, `ipv6` and `ipv4` stay distinct. `auto` is not a recorded transport.

The public array has **no version marker**. The caller must establish that its
input is the current normalized summary, whose latency aggregates mean ICMP
RTT. The legacy daemon's version-1 stored file instead held HTTP proxy-delay
aggregates; its loader resets those aggregates during version-2 normalization.
This library neither detects that provenance from a summary nor performs or
proves that migration. Both version-1 and version-2 persisted `{version, entries}`
envelopes are rejected. A producer cannot prove ICMP provenance by supplying
the same field names.

`samples`, relay-pass, ready, failed, consecutive-failure and latency counts
retain their separate meanings. Relay liveness alone is not service readiness.
The computed ready ratio is absent for zero observations, which a display must
show as unknown rather than 0% failure or 100% success. The explicitly named
`effective_readiness_rate` additionally exposes the existing Swift fallback
(0 at zero samples) only for compatibility. A supplied non-null ratio must agree
with the counts within absolute tolerance 1e-12; it cannot override them.
Serialization preserves supplied null/absent ratios as null, while the computed
accessor can derive a positive-sample ratio. Ruby's canonical snapshot always
recomputes that field; the shared test checks this distinction.

The confidence score matches Ruby and Swift: Wilson lower bound at z=1.96,
minus `min(consecutive_failures, 3) * 0.04`, or -1 for zero samples. A single
1/1 success therefore does not outrank sustained 20/20 evidence. Negative scores
are meaningful and are not clamped. This is a historical display statistic,
not a current connection or candidate readiness assertion.

Optional latency/timestamp/source data remain unknown when missing or null;
missing values are never converted into zero RTT, current time or new samples.
Timestamp strings are bounded opaque display labels, not validated chronology.
There is no time comparison, 600-second freshness inference, transport selection,
recovery ranking, history accumulation, EWMA update or protected-circuit evidence
reuse. Those require separate owner/provenance contracts.

## Bounds and deliberate hardening

- JSON array body: 1..1,048,576 bytes, at most 1,024 rows; an empty array is valid.
  The byte bound precedes decoding and bounds temporary decoder allocations.
  Over-limit or invalid input fails the whole snapshot, with no truncation or
  partial replacement. Serialization has the same body cap.
- Integers: nonnegative JSON integers through 9,007,199,254,740,991, preserving
  exact future JavaScript-number representation. No strings/floats/coercion.
- `ready <= relay_pass <= samples`; `failed == samples - ready`;
  `consecutive_failures <= failed`; `latency_samples <= samples`.
- Relay IDs: 1..255 ASCII lowercase letters, digits or hyphens. Duplicate
  relay/transport pairs fail; output uses deterministic relay/transport ordering.
- Finite nonnegative latency values use the same safe numeric ceiling. Present
  best/last/worst integer values must be ordered. Zero latency samples cannot
  carry measurements; positive latency samples may still have unknown optional
  aggregates. No absent measurement is synthesized.
- Timestamps: 1..64 printable ASCII bytes if present. They are labels only.
- Sources: at most 32 unique keys of 1..64 lowercase ASCII letters, digits,
  hyphens or underscores. Counts cannot exceed samples in total. Missing or
  partial legacy counters are retained as such. Duplicate source keys fail.
- Unknown row fields and duplicate known JSON fields fail. In particular,
  `last_result`, secrets and persisted-file envelope fields are not accepted.
  Output uses only the typed public field allowlist. Error categories are fixed;
  errors never echo input values or parser text.

These rules are intentional Windows hardening, not a claim that every malformed
Ruby/Swift input behaves identically. Existing Ruby/Swift production code remains
unchanged. Allowlisting fields is not a general secret-content detector; callers
must still provide properly sanitized public labels. Rejecting an input does not
authorize deleting, repairing or replacing its source file.

## Future UI / IPC integration boundary

The mock IPC still has only its existing commands, a 64 KiB frame cap, and no
history endpoint. This library's 1 MiB cap is **not** permission to enlarge an IPC
frame or attach the whole array to Snapshot. A later read-only history bridge
needs a versioned/capability-negotiated bounded page DTO, including an explicit
synthetic/live provenance label, boot ID and snapshot sequence, and a cursor
bound to that same immutable snapshot. Page encoding must fit the actual frame
including envelope overhead and must not split rows. Page exhaustion, empty
history, failed load and unsupported capability must remain distinguishable.
Changing snapshots while paging must reconcile/restart rather than mix pages.

A future renderer must keep synthetic examples visibly labelled, preserve the
last coherent view or show an explicit loading/error state on failure, discard
late responses after navigation/newer requests, and display no-observation and
unknown latency/time explicitly. Statistics and synthetic data must never enter
candidate validation, recovery, policy persistence or engine ownership. No UI
behavior or pagination implementation is delivered or accepted here.

## Tests

The shared fixture contains nine synthetic summaries. Rust validates fields,
optional fallbacks, roundtrip, sorting and identity, bounds and malformed inputs.
Ruby tests invoke the actual public snapshot and confidence functions, checking
recomputed ratios, sorting, removal of `last_result`, nonmutation and detached
public results. Swift tests decode the same file with the actual client model
and check scores, optional fallback and transport separation. The shared corpus
does not establish arbitrary-input equivalence or live-history acceptance.

Existing workspace/Ruby/Swift CI commands discover these tests automatically.
Rust minimum-version checks and Windows/macOS execution remain their respective
CI gates; a local newer-toolchain result or a fixture pass does not satisfy
installation, native UI, real history migration or VPN acceptance.

## Candidate payload regression gate

The installer executes every packaged `daemon/test_*.rb`, so passing tests in a
full source checkout alone cannot establish that a candidate is self-contained.
`scripts/stage-daemon-payload.rb OUTPUT_PAYLOAD_DIRECTORY` copies an explicit
allowlist: the daemon source, all daemon test files, the synthetic watchdog test
dependency, and the three shared DNS/catalogue/history fixture JSON files at
their original relative paths. It does not copy the full core tree or user data.
The watchdog regression supplies a fake CLI and keeps its action path disarmed.

The helper preflights all required regular files, refuses existing destination
files or symlink targets, then uses `RbConfig.ruby` to syntax-check and execute
all staged daemon tests with the actual payload as the working directory. Missing
fixtures or failed regressions abort assembly; tests never silently skip missing
data. The caller supplies a dedicated, trusted build-output location. A partial
output after a copy/test failure is retained for diagnosis and is not a successful
candidate; retries use a fresh location rather than overwrite existing files.

Both the macOS candidate assembly and the Windows migration workflow's macOS
compatibility job use this same helper. Thus feature-branch CI exercises the
packaged layout even when the candidate workflow does not trigger. This gate
does not run the installer, control a service, build the app/PQ helper, or prove
installation or live-network acceptance. Removing any required shared fixture
from the source must fail staging; removing it from an already staged payload
must fail the corresponding regression rather than fall back to the checkout.
