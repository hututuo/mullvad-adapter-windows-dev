# Owned inner-DNS transport

`dns_transport::for_worker` is an explicit library entrypoint, not wired into
mock IPC, the desktop, Worker startup or domain readiness. It borrows an owned
process and its BoundNetwork guard, then connects only to127.0.0.1 on the supplied
mixed listener. Before any SOCKS bytes are sent, the retained process handle and
reverse established TCP four-tuple must match. Ownership is checked again before
accepting a response; an exited peer or a peer already closing can fail closed.
The caller must supply the mixed port from the owned worker instance, not a
renderer-selected arbitrary endpoint.

The destination is fixed10.64.0.1:53 in an IPv4 SOCKS5 CONNECT request; the only
question is `www.gstatic.com` IN/A. No system DNS, proxy environment, redirects,
connection pool, authentication fallback or direct-network fallback is used.
The transaction ID comes from the OS-backed getrandom API. Require no-auth
SOCKS5 negotiation, success/version/reserved fields, bounded IPv4/IPv6/domain
bound-address framing, and a12..65535-byte DNS-over-TCP response. The shared
adapter-probe validator checks the full payload. Every outcome drops the socket.

One two-second deadline covers connect, ownership verification, SOCKS, DNS and
parsing. Connect is capped at500ms; reads/writes use at most50ms wait slices and
recheck cancellation/deadline on every partial operation. Each completed phase
and final success checks the deadline. Kernel calls such as socket connection,
process-table querying or entropy acquisition cannot be forcibly interrupted by
this function; a delayed return is not accepted after the deadline, and the
resource owner remains responsible for not replacing a still-running worker.
This is an acceptance deadline, not a promise that every OS call returns in2s.

`ValidatedA(count)` is only syntax/question/answer evidence. It does not prove
that the returned address is reachable, that a WAN socket is physically bound,
that WG/SS is working, or that a candidate can be committed. The caller must
still attach operation/path/attempt/time evidence and pass the normal owner
and domain freshness checks. IP/HTTPS canaries and live integration are separate.

## Tests

Fourteen portable tests use actual loopback TCP peers and threads, covering
segmented positive SOCKS/DNS, no bytes on ownership refusal, invalid SOCKS fields,
header-only DNS, cancellation during a stalled read, total deadline under slow
bytes, loss of ownership after response, no connect when cancelled/invalid, and
bounded IPv6/domain bound-address forms. Additional review regressions exercise
malicious ID/question/flags/count/large-tail frames, invalid negotiation, empty
SOCKS domain and truncated DNS, and cancellation/deadline during the final owner
check. A forced-nonblocking accepted socket regression checks that fixture peers
restore blocking mode before blocking I/O on every platform. Portable verifier callbacks are test
fixtures and do not prove Windows process ownership.

One Windows test launches a synthetic SOCKS/DNS child with sanitized environment
and an owned Job. It verifies a foreign parent listener receives zero bytes,
then accepts the actual child response using the real TCP owner-table proof and
waits for successful child exit. One ignored child fixture is invoked explicitly
by that test; no blanket `--ignored` run is needed. The Windows test bodies are
also type-checked with the windows-api-check feature, which is not execution.
All fixture endpoints stay on loopback and return documentation-only addresses;
no fixture forwards the encoded resolver request to an actual network.
