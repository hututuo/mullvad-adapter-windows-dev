# Owned loopback controller, first integration boundary

The Windows factory requires an OwnedProcess handle, not a PID or caller-selected
URL. It retains only a duplicated process handle, not the kill-on-close Job
handle. Each request establishes a new IPv4 loopback TCP connection, then checks
the Windows owner table for the reverse ESTABLISHED four-tuple and that retained
process's PID. The retained process object must be unsignalled before and after
the query; exit code259 is not confused with a running process. A listening port
or a coincident PID alone never authorizes transmission. No HTTP/capability byte
is written before this verification succeeds within the connection budget.

This verifies the socket's owning process, not the executable's vendor identity.
The caller must separately verify the packaged binary/hash and keep the process
and configuration under the existing Job/private-file lifecycle. It does not
protect against administrator/kernel interference or injected code in the owned
process. The TCP table is read-only and not logged/exported. Its traversal is
capped at16384 rows, allocation at4MiB, with at most3 size-change attempts.
Windows table queries are synchronous; late results are discarded before HTTP,
but the kernel call itself cannot be force-cancelled. Run outside the actor.

The HTTP layer pins ureq3.4.2 with default features disabled. JSON serves this
controller; the separately reviewed HTTPS canary adds rustls to the package's
unified dependency graph. This controller still has no environment/system proxy,
redirect, cookies or TLS connector; only the fixed
127.0.0.1 endpoint is constructible. The custom connector rejects other URI/ports
and proxies, and there is no pooled connection reuse. Connect/proof has a500ms
acceptance budget; each request has a2s deadline, response headers max8KiB, body
max16KiB. The custom transport applies remaining deadlines to partial writes and
reads, including slow bodies, and clears its output buffer after transmission.
The fixed64-hex capability is kept in a Zeroizing string and its HeaderValue is
marked sensitive. Third-party header allocations and OS transport copies are not
claimed to be securely erased; no credential/header/error body is exposed in
ControllerError or ordinary Debug output.

The supported calls are pinned version check, read fixed OUT selector, and select
REJECT/SLOT-A/SLOT-B. A read verifies selector type, exact member set and selected
member. A mutation is attempted once. A lost response or ambiguous server status
returns OutcomeUnknown; the transaction owner must reconcile through a fresh
read under the current generation/epoch before any retry. An HTTP204 is only a
controller acknowledgement, not a tunnel canary or policy commit. Atomic selector,
policy file and in-memory publication remain owner-level integration gates.

The factory is not wired into the mock agent, and no real process is launched by
this module. Portable tests use unique ephemeral loopback fixtures. Windows tests
spawn only this repository's child test executable inside an owned Job and check
correct-owner, different-live-owner and exited-owner cases; no user service is
contacted. Normal Mihomo launch, transient private configuration, actual vendor
controller compatibility, route binding, handshake, recovery and PQ remain
separate tests after these foundations pass. The parser-only gate stays separate.

Core Cargo.lock includes optional ureq cookie/url/ICU/time dependencies that are
not in the selected normal dependency graph. Some unused optional packages have
higher MSRVs; the original selected controller graph was verified on Rust1.85.1. The
workspace now requires Rust1.88 for the separate DNS protocol dependency; the
controller fixed-HTTP transport remains unchanged; the separate HTTPS canary
feature review and exact rustls pin are documented in HTTPS_PROBE.md.
Do not enable those optional features without a separate MSRV/security review.
ureq's custom connector API is explicitly unversioned, so its exact dependency
version is pinned and upgrades require recompilation and these ownership tests.

Primary references:
- https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable
- https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_pid
- https://docs.rs/ureq/3.4.2/ureq/unversioned/transport/index.html
- https://github.com/MetaCubeX/mihomo/blob/v1.19.31/hub/route/proxies.go

## Optional official front lifecycle gate

The Windows CI parser driver additionally invokes synthetic_lifecycle after
verifying the official archive size/SHA and -v output. The fixture uses only
public synthetic capability bytes, a unique private runtime directory, sanitized
Job launch and read-only private stdin with -f -. It creates the generated front
only, whose selection starts at REJECT; no WG/SS worker, VPN peer, TUN, DNS or
route is started. Ephemeral loopback ports are reserved until immediately before
launch; a port collision fails through startup/ownership checks, never falls
back to a different process or credentials.

It waits for pinned version, OUT/REJECT and connected mixed-TCP process ownership
together because the upstream controller starts before proxy/listener setup.
The mixed probe completes only a TCP handshake and sends no application data.
A second explicit occupied-mixed negative control keeps the parent listener
alive, waits for the real controller/selector, and requires ownership refusal.
The ordinary positive fixture verifies re-read REJECT, a REJECT-only mutation,
wrong-capability refusal by the actual vendor controller, owned Job stop, refusal
after exit and transient input cleanup. Startup reads may poll for15s; each
request retains its own2s bound. Mutations are not retried. Python caps the entire
fixture subprocess at50s (positive, occupied-mixed, and late-start cancellation
modes run separately). Job handles close on abnormal fixture termination.

This CI executable is not a production binary loader: its supplied vendor path
is trusted only because the enclosing driver just verified the pinned official
archive. Packaging/hash verification at production launch remains a separate
implementation gate. Successful execution establishes front lifecycle/controller
compatibility only, not any tunnel, route binding, canary, recovery, PQ, installed
service or end-user GUI acceptance. Linux retains the parser-only gate.

The reusable `lifecycle::Front` and control `ResourceOwner` now host that same
front-only fixture. Owner generation preemption and a late-start cancellation
barrier exercise worker-side Job stop and input cleanup. See
`../control/OWNED_LIFECYCLE.md` for acceptance deadlines, sticky cleanup failure
and cooperative cancellation boundaries. This does not enable live VPN commands.
