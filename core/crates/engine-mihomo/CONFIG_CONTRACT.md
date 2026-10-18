# Mihomo configuration contract, first executable slice

This pure crate emits bounded JSON (a YAML-compatible representation) for a
fixed front and one worker. It does not start a process, acquire a peer, read a
real identity, create a listener, write a secret file or change routing.

Compatibility target: Mihomo v1.19.31. Official Linux/Windows x64 parser artifacts
are version/byte-count/SHA256 pinned in engines/mihomo-compatibility.json. They are
used transiently for CI parser checks only; no binary is committed, bundled or
installed. The manifest links upstream GPLv3 and source; complete redistribution
and third-party notices remain packaging gates.

Worker graphs preserve direct IPv4, direct IPv6 and WG-over-Shadowsocks semantics.
Only the outer transport carries an explicit interface alias; IPv6 outer WG does
not force ip-version=ipv6 on inner traffic. SS uses the supplied literal inlet and
Mullvad aes-256-gcm transport, with WG target127.0.0.1:51820 through that inlet.
Tunnel DNS is tcp://10.64.0.1; standalone DNS and OS TUN are disabled. Optional
static PSK is preserved but never counts as PQ. Required multihop or PQ fails
closed in this slice, pending their separately validated graph/helper support.

Both front and worker listeners/controllers are explicit loopback-only with an
input64-hex controller capability. The caller MUST supply a CSPRNG-generated,
per-instance secret; syntax validation does not prove entropy. Port ownership,
cross-process/controller collisions and authenticated HTTP control are not
implemented by this pure builder. Front choices start with REJECT and never
include DIRECT. store-selected/store-fake-ip are explicitly disabled so a previous
Mihomo selector cannot restore an unvalidated slot. Controller CORS uses a
nonempty allow-origins list containing only an empty string: the pinned chi
v0.1.1 dependency interprets an empty list as wildcard, while this entry cannot
match a nonempty browser Origin. Capability authentication remains required;
CORS is not authorization and does not restrict ordinary local clients.
No geodata auto-update,
standalone DNS, NTP or sniffer is enabled by this configuration.

The caller supplies an egress alias plus nonzero LUID/index and family evidence;
these are input checks, not authorization or a proof of binding. Before launch,
the platform owner must revalidate current physical identity/alias and actual
endpoint egress. Upstream v1.19.31 resolves aliases from a20-second interface cache
and Windows binding has special handling for non-global destinations. Fresh
metadata and an interface-name field alone do not prove no external-TUN loop.
No binding success, leak protection, reachability or live VPN readiness is claimed.

Input secrets are borrowed. Serialization writes directly to a fixed-capacity,
size-limited zeroizing byte owner without a reallocating/intermediate JSON value.
The output has no Debug/Clone/Serialize; explicit copies remain the caller's
responsibility. Private runtime-file creation/ACL/crash cleanup and Job Object
launch are implemented separately; positive worker integration remains unverified. Parsing verifies key representation, not that a
private key belongs to the chosen Mullvad account or matches a public identity.

Tests inspect synthetic graph fields, reject unsafe endpoints/invalid keys,
family/port/profile mismatches, preserve static PSK without PQ downgrade, and
prove the bounded writer does not reallocate. The synthetic_config example only
accepts four fixture mode names and never accepts account/key arguments.

scripts/test-mihomo-config.py validates official artifact hashes, expands only a
bounded flat executable, clears CLASH_* overrides, then runs -t -f - with synthetic
stdin and a new temporary home. Upstream main returns after parsing before hub
startup. A deliberately bad synthetic private key must fail. Windows/Linux jobs
have subprocess and overall job timeouts. This is real engine parser validation,
not WG handshake, SS, DNS, egress or PQ acceptance. It never supplies real
credentials. Its separate Windows-only official front fixture starts a REJECT
front in normal engine mode; see the owned lifecycle contract for its seven
control-plane/cancellation gates.

Primary implementation references (v1.19.31):
- https://github.com/MetaCubeX/mihomo/blob/v1.19.31/main.go
- https://github.com/MetaCubeX/mihomo/blob/v1.19.31/config/config.go
- https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/wireguard.go
- https://github.com/MetaCubeX/mihomo/blob/v1.19.31/component/dialer/bind_windows.go
- https://github.com/MetaCubeX/mihomo/blob/v1.19.31/component/iface/iface.go

- https://github.com/MetaCubeX/chi/blob/v0.1.1/cors/cors.go

`worker_with_route` is the checked configuration entry for the candidate worker factory:
it requires a fresh read-only `EgressSnapshot` matching the exact endpoint and
caller egress alias/LUID/index/family, before and after serialization. See
`../platform/EGRESS_SNAPSHOT.md`. The pure serializer remains for parser fixtures.
This entry does not prove actual socket binding. The separate Worker::start
factory now connects it to private input/owned process startup under BoundNetwork;
no user-facing host command enables that path and positive VPN acceptance remains
NOT_RUN. See WORKER_LIFECYCLE.md.

## Authenticated owned-carrier configuration

`worker_with_carrier_route` retains the same route-input checks and accepts a
fixed IPv4 loopback SOCKS5 carrier with a borrowed 64-hex capability. Direct WG
uses `dialer-proxy=CARRIER`; SS uses `SS-INLET.dialer-proxy=CARRIER`, retaining the
inner WG destination `127.0.0.1:51820`. The carrier never appears among OUT choices.
Physical `interface-name` is absent from all loopback dials; the actual physical
binding belongs to the retained owned UDP socket. A carrier port must differ from
both worker listeners. Capability bytes enter only private configuration input.

This serializer does not start a carrier or enable a product connection. A host
must authenticate its accepted TCP peer against the retained engine process before
credentials, require SOCKS username/password, and assign a dedicated association
UDP port. Pinned Mihomo sends UDP ASSOCIATE with `0.0.0.0:0` before opening its UDP
socket, so admission cannot infer its UDP source from the TCP source port. The
first actual sender must be latched only after fixed destination/framing checks
and `ControllerOwner::verify_udp_sender`; that API accepts a unique covering
IPv4/IPv6 wildcard row only for the retained live PID. Ambiguous or foreign rows
are rejected. Its table read is an ownership snapshot, not per-packet MAC or a
guarantee against all same-user socket-reuse races. Required canary, epoch,
actual socket witness and cleanup gates remain separate.

- [Pinned SOCKS5 UDP association](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/socks5.go)
- [SOCKS5 UDP lifetime and framing](https://datatracker.ietf.org/doc/html/rfc1928#section-7)
- [SOCKS username/password authentication](https://datatracker.ietf.org/doc/html/rfc1929)
