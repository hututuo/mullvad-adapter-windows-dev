# Read-only Windows physical attachment sampling

This is a platform sampling/classification primitive, not yet attached to the
agent recovery actor. It does not open network sockets, query DNS/proxy/websites,
change routes/adapters, bind Mihomo egress, or claim Internet/tunnel readiness.

`GetIfTable2` supplies hardware/filter/endpoint/tunnel/link and transient LUID/index evidence.
`GetUnicastIpAddressTable` supplies preferred usable IPv4/IPv6 addresses. Interface
metadata is read before and after the address table; changed, inconsistent,
oversized or late samples are unknown. Only Ethernet, Wi-Fi, WiMax and mobile
broadband hardware are classified; unrecognized hardware cannot assert an outage.
Virtual, loopback, filter, endpoint-only and tunnel interfaces do not establish physical recovery.
Unknown media/operational state or no discovered physical hardware remains unknown.
Positive evidence from one supported physical link can coexist with another
ambiguous link. Link-local, loopback, unspecified, multicast, broadcast, IPv4-mapped
IPv6 and non-preferred addresses are not usable attachment evidence.

LUID and index must both match within the sample. Neither is a persistent identity
or authorization token. Returned family flags are candidates for later egress
selection, not proof of actual socket binding or exclusion from an external TUN.
No MAC, adapter alias, description or address is printed or serialized here.

Traversal is capped at4096 interfaces and16384 addresses. An observation finishing
at/after two seconds is discarded. The underlying Windows calls are synchronous;
this does NOT impose a two-second kernel-call timeout. Integration must run one
bounded/single-flight observer outside the transaction actor, convert read errors
or missed deadlines to unknown, bind observations to current generation/epoch,
and retain the existing offline latch on unknown. That worker lifecycle and the
recovery integration remain gates. Before/after tables detect observed changes,
not every possible change-and-return race; real unplug/sleep/TUN scenarios remain
required and this primitive is not a substitute for them.

Portable tests cover virtual-TUN survival, alternative IPv4/IPv6 physical links,
unknown/empty/unsupported hardware, unusable addresses, identity churn, positive
versus ambiguous evidence and deadline boundaries. The Windows native test reads
its CI runner's tables without expecting an Internet connection or physical NIC.
It never modifies runner network state. Signature checks alone are not native
execution. Real Windows Wi-Fi/Ethernet transitions and Mihomo egress remain untested.

Primary references:
- https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getiftable2
- https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_row2
- https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getunicastipaddresstable
