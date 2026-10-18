# Read-only, interface-constrained egress snapshot

`egress::windows::snapshot` takes an already selected physical LUID/index and an
explicit IP endpoint. It does not choose an interface, resolve DNS, query a proxy,
open a socket, send a packet, or change routes/adapters/DNS. All potentially blocking
Windows reads belong on an I/O worker. There is no kernel cancellation claim.

The sequence is GetIfEntry2, GetBestRoute2 constrained by that LUID/index,
GetUnicastIpAddressEntry for its selected source, a second constrained route read,
and a second interface read. Shared physical classification rejects non-hardware,
filter, endpoint-only, tunnel, loopback, unsupported or non-up interfaces and
unusable/unpreferred/SkipAsSource addresses. Both identities and decoded aliases
must agree before/after; the route/source/prefix/next-hop/scope/metric fingerprint
must agree. The chosen source must belong to the requested interface and endpoint
family. The returned prefix must cover the requested destination. Local/private,
loopback, multicast, link-local and mapped endpoints are rejected; this is not an
exhaustive registry of all reserved public address ranges. IPv6 link-local next
hops remain valid for a selected interface, while an explicit nonzero scope must
match its index. A zero next hop is valid for an on-link route.

Route valid lifetime and source valid/preferred lifetimes must each be at least
3 seconds at read time. Known0/1/2-second values are rejected, conservatively
covering the2s snapshot window with an integer-second boundary margin.
The full read/classification must finish before2s from its start. The immutable
snapshot retains that start instant, so its remaining TTL includes collection
and queue delay. `worker_with_route` additionally checks exact endpoint, alias,
LUID/index/family and freshness before and after configuration serialization.
The existing pure `worker` serializer remains for sanitized fixtures; a real host
must use the checked route path and its own current operation/hint guard.

This is point-in-time configuration evidence, not a verified socket or proof that
Mihomo sent a packet on the chosen interface. An interface/route change after the
read can invalidate it. The future candidate owner must discard it when its token
or relevant network hint changes, revalidate before launch/commit, and verify the
actual endpoint egress. Route-change notifications feed the observation revision, and the optional
ResourceOwner network-bound guard cancels stale candidates. Actual bound-socket checks,
external-Clash no-loop behavior, multi-NIC failover and live VPN acceptance are
still separate gates. The separate worker factory re-reads this evidence before control-plane readiness;
no user-facing worker command is enabled by this API.

Thirteen portable platform tests cover identity/alias/route changes, physical/source
classification, IPv4/IPv6 prefixes and family, exact2s expiry, invalid next hop
and scope, unsafe endpoints/aliases, short-lifetime rejection, and independent route-fingerprint comparison. One engine test covers exact route-input
matching. Two Windows tests check sockaddr byte order and an actual constrained
loopback route lookup on an existing enumerated interface, without packets. The
loopback path is then explicitly rejected by the public egress API. These tests
do not prove a positive physical-WAN route or real Mihomo socket binding.

Primary contracts:
- [GetBestRoute2 interface constraints](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getbestroute2)
- [GetIfEntry2 identity and alias](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getifentry2)
- [GetUnicastIpAddressEntry source ownership](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getunicastipaddressentry)
- [Pinned Mihomo Windows socket binding](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/component/dialer/bind_windows.go)

## Owned UDP carrier boundary

`windows_datagram::OwnedDatagram` opens its own non-inheritable UDP socket from a
fresh physical snapshot. It binds the exact source address with exclusive use,
sets and reads back the unicast interface and packet-info options, and uses
provider-specific SendMsg/RecvMsg functions. Separate IPv6 sockets require
V6ONLY; mapped IPv4 and scoped relay endpoints are rejected. Calls are synchronous
and nonblocking, so no pending I/O borrows a returned stack buffer.

Each submission includes source/interface pktinfo. Receive data escapes only
with the fixed relay address/port, exact local destination and receive interface;
missing, duplicate, malformed or truncated ancillary data is rejected. Normal
close reports errors explicitly; Drop is only a fallback. No payload is logged.

The opaque window/witness is tied to a monotonically allocated socket instance;
only its still-owned socket can validate it against a fresh snapshot. It proves
successful socket submission and matching receive metadata, **not** NIC-level
transmit capture, packet authentication, arrival time or a request/response
match. A previously queued packet can be dequeued inside a new window. A host
must additionally bind its successful, fresh tunnel canary to the same operation,
worker instance and network revision. WFP redirection is not excluded by this
primitive alone. It does not enable front selection or Connect by itself.

The native loopback fixture exercises real provider lookup, send, receive
pktinfo, readback and checked close without contacting a relay. The public
constructor cannot use the fixture's loopback path. A successful fixture is
separate from real physical-WAN, carrier integration and VPN acceptance.

- [IPv4 unicast interface byte order and readback](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options)
- [Receive pktinfo address and interface](https://learn.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-in_pktinfo)
- [SendMsg socket/provider contract](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasendmsg)
- [ReceiveMsg extension lookup](https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_wsarecvmsg)
