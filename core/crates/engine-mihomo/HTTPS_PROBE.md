# Owned HTTPS canary transport

This library entrypoint is not wired into Worker startup, mock IPC or domain
readiness. It accepts only two fixed targets, preserving the existing Ruby
canary intent: `https://1.1.1.1/cdn-cgi/trace` and
`https://www.gstatic.com/generate_204`. They have eight- and twelve-second total
acceptance budgets respectively. A validated HTTP status in200..399 passes;
redirects are not followed. This preserves the old status classification rather
than introducing a new success definition or changing IP/HTTPS degradation rules.

## Connection and DNS boundary

Each call makes one new connection to the worker's supplied127.0.0.1 mixed port.
The retained process handle and reverse established TCP four-tuple must match
before any SOCKS or TLS bytes are sent. The IP target uses SOCKS IPv4 address
1.1.1.1:443; the hostname uses SOCKS domain-name form, delegating resolution to
that peer. The custom resolver returns only a local placeholder address after
checking the exact fixed URI. It never invokes DefaultResolver, ToSocketAddrs,
a system resolver or the network. The custom connector has no fallback TCP path.
There is no environment/system proxy, connection pool, cookie jar or redirect
fallback. The worker configuration separately requires WireGuard remote DNS;
these local tests do not prove the actual engine's WAN/DNS behavior.

After receiving and fully consuming the response, the original owned process
must still be alive; its retained handle prevents PID reuse. Unlike the DNS
transport's final established-tuple check, HTTP permits orderly peer closure
after a complete authenticated response. The same connected socket carries the
entire SOCKS/TLS exchange; it is never replaced or pooled. Cancellation and the
total deadline are checked again after the final process check.

## TLS, bounds and cancellation

Ureq3.4.2 uses a custom owned-SOCKS connector chained directly to rustls. Pin
rustls0.23.45, with the ring crypto provider selected explicitly, normal server
certificate/hostname/IP validation, Mozilla WebPKI roots and no client key.
Production callers cannot supply alternate roots or disable verification. No
platform verifier or AIA fetch is enabled; fixture roots remain process-local.

The version pin includes the upstream fix for
[GHSA-2mjx-qc3c-rqvc](https://github.com/rustls/rustls/security/advisories/GHSA-2mjx-qc3c-rqvc):
[0.23.45 release](https://github.com/rustls/rustls/releases/tag/v%2F0.23.45).
The issue concerns TLS1.3 handshake messages crossing encryption-level
boundaries, not a claim that an on-path attacker can forge a completed handshake.
The selected runtime graph uses ring/WebPKI, not aws-lc, native-tls or a system
proxy feature. Rcgen0.14.10 is test-only and generates ephemeral certificates and
keys in memory; only a public test certificate is exchanged with the child
fixture. Nothing changes the OS trust store and no private test key is saved.

Response headers are limited to8KiB and the complete body to64KiB (one byte of
bounded lookahead handles the exact upper boundary). Compression features are
disabled. TCP connect is capped at500ms; partial reads/writes poll cancellation
at most every50ms and use the same operation deadline throughout SOCKS, TLS and
HTTP. A cancelled transport uses a terminal I/O error, not Interrupted, which
some libraries would retry indefinitely. OS connect/ownership/entropy calls
cannot be forcibly interrupted; late results are refused. No body/status becomes
an accepted canary after cancellation, expiry or process death.

The cloneable BoundCancellation monitor contains only a hint revision and shared
cancel flag. It cannot expose a physical binding, construct a BoundNetwork or
start/commit any operation. It lets the HTTP library own a callback while the
resource owner retains operation authority. Probe results still require the
owner/path/attempt/timestamp evidence before domain use; HTTPS success alone is
not proof of a VPN, physical socket binding or an acceptable protected candidate.

## Validation scope

Ten portable tests use actual local SOCKS/TLS peers, normal certificate
verification and process-local generated roots. They cover IP/name forwarding,
trusted positives, untrusted/wrong-name/wrong-IP/expired/future certificate
negatives before HTTP, zero bytes after
owner refusal, fixed resolver rejection, redirect non-following, exact64KiB/
oversize/header/truncated-body boundaries, slow reads, cancellation and a late
final owner check, final process death, and chunked/EOF body boundaries. HTTP
receivers assert the expected SNI/Host and absence of Authorization/Cookie. One additional control test exercises a detached cloned
monitor across actual threads for both owner cancellation and a notification
without owner polling.

One Windows test starts a sanitized owned-Job synthetic TLS child, uses the real
process/TCP proof before SOCKS and the retained process after HTTP, then signals
completion and waits for exit. One ignored fixture is called explicitly. Its
root is accepted only by that private test configuration, never by the production
entrypoint. Windows tests are type-checked with windows-api-check, but actual
Windows execution and minimum Rust1.88 builds require exact-SHA CI. All fixture
sockets are loopback; no test sends an actual Cloudflare/Google/Mullvad request.
