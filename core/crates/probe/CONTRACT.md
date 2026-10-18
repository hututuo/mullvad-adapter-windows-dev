# DNS canary response contract

This crate is a pure IN/A response validator. It opens no socket, resolver,
configuration file or cache. The caller provides the already framed DNS payload,
transaction ID and ASCII question. A positive count proves only that this payload
contains related A answers. It does not prove DNSSEC, data-plane reachability,
account identity, a working tunnel, or permission to commit a candidate.

Before decoding, accept 12..65535 bytes, exactly one question, a nonempty answer
section and at most4096 total records. Require matching ID, QR=response, QUERY
opcode, TC=0, reserved Z=0 and base RCODE=0. Hickory decodes all sections; reject
any error or trailing bytes. The decoded (including EDNS extended) RCODE must be
NoError. The question must match case-insensitively, with typeA/classIN. Only
IN/A records at that name or the end of an unambiguous <=16-hop CNAME chain count.
Reject cycles, conflicting aliases, and an A+CNAME owner. Unknown records cannot
supply A evidence. A/AAAA-only distinction and authority/additional malformed
names are covered by raw-wire fixtures.

The question API deliberately accepts bounded ASCII labels (letters, digits,
hyphen and underscore), optionally with a trailing dot; it does not accept IDNA,
zone-file escapes or arbitrary binary names. The production canary question is
an ordinary ASCII hostname. No global DNS cache or dynamic resource-class table
is used by this crate.

## Shared evidence and differences

The70 synthetic wire cases are consumed by Rust and Ruby. Ruby runs them both
against its decoder and over a real Socket.pair/thread with DNS-over-TCP framing.
They cover compressed/uncompressed and multiple A answers, case folding, CNAME,
valid AD/CD/NS/OPT, opaque unknown records, header/count/ID/question/flags errors,
truncation/trailing data, compression bounds, nested name length, and hop limits.
Rust additionally rejects every truncated prefix of every positive frame and
executes deterministic byte mutations.
These cases establish agreement only on this corpus, not complete parser
interchangeability. Both implementations now reject EDNS extended errors, duplicate/misplaced/nonroot
OPT records and incomplete option envelopes. Unknown option values remain opaque.
The Rust adapter adds an explicit envelope walk with Hickory Name/Query readers
because Hickory itself deliberately tolerates incomplete OPT options. Rust's
bounded ASCII expected-question API is an explicit delta; library-specific known
option value validation can also be stricter than the Ruby opaque values. Ruby
checks SVCB/HTTPS priority/target and ordered key/length/value envelopes locally,
without invoking the stdlib's global SvcParam dynamic-class cache. Service values
remain opaque and cannot supply A evidence; both accepted and rejected frames
are covered by global-cache/constant-count stability tests.
No live DNS request is part of these tests; SOCKS ownership, framing deadlines,
cancellation and actual IP/HTTPS canaries remain separate integration gates.

## Dependency and toolchain choice

`hickory-proto=0.26.3`, default features off, only `std`. The selected dependency
graph does not enable DNSSEC, TLS, tokio, hickory-net, a resolver or an async
runtime. Cargo's lock may include unused optional/target-only packages; that is
not evidence they are linked. The library still includes non-network support
code (IDNA/URL/random facilities); this wrapper invokes only binary decoding and
bounded ASCII name construction.

The core minimum Rust version moves from1.85 to1.88, matching the dependency's
published requirement. Comparison:0.25.2 supports1.71.1 and could serve a bounded
pure-decoding use without the DNSSEC path; it is not categorically unsafe.
However,0.26 separates the protocol library from the network layer and is the
current maintained release line. Both0.26.1 and0.26.3 require1.88, so taking0.26.1
would not preserve the old compiler. Choose0.26.3 for the current protocol fixes
rather than adding a new dependency already behind that supported line.

Official advisory boundaries:
- [RUSTSEC-2026-0118](https://rustsec.org/advisories/RUSTSEC-2026-0118.html)
  concerns DNSSEC closest-encloser validation, absent from this selected feature
  graph and wrapper; it is not evidence against every0.25 decoder call.
- [RUSTSEC-2026-0119](https://rustsec.org/advisories/RUSTSEC-2026-0119.html)
  concerns encoding compression complexity, fixed>=0.26.1; this wrapper does not
  re-encode untrusted messages.
- [v0.26.3 release](https://github.com/hickory-dns/hickory-dns/releases/tag/v0.26.3)
  and the published crate manifest establish the selected version/MSRV.

CI pins1.88.0 for all core/parser jobs on Linux/macOS/Windows; Tauri retains its
separate newer toolchain. Exact run results belong in the private verification
record. A build on a newer local compiler does not prove the minimum compiler.
