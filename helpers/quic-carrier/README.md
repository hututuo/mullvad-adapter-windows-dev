# Official QUIC carrier

This bounded helper links the official Mullvad MASQUE/HTTP3 client at the pinned
2026.5 SHA. It owns no VPN identity and does not install a TUN. The parent adapter
provides official relay metadata and a physical interface/source. macOS uses
IP_BOUND_IF/IPV6_BOUND_IF, Windows uses IP_UNICAST_IF/IPV6_UNICAST_IF plus a source
bind, and Linux uses SO_BINDTODEVICE. Failed binding never uses a default route.

One schema1 JSON request on stdin contains remote_endpoint, server_hostname,
auth_token, target_endpoint127.0.0.1:51820, interface_index, interface_name,
source_address and mtu. All remote endpoints use the official QUIC443 constant.
No device key enters this process. Never put requests/tokens in argv or logs.

Ready is emitted only after verified QUIC/TLS/HTTP3 CONNECT. It includes the local
loopback UDP endpoint and bound interface receipt, **not** WireGuard readiness.
Full IP/inner-DNS/HTTPS canaries and a current route/epoch are still required.
The parent retains stdin; `{"action":"stats"}` requests bounded packet counters,
`{"action":"stop"}` or EOF stops forwarding. A visible WG response packet is not
cryptographic authentication. Only the first local sender can use an instance.

`cargo +1.97.1 test --manifest-path helpers/quic-carrier/Cargo.toml --locked`
runs loopback/IPC fixtures without an account or real relay. `--version-json`
identifies the protocol and upstream pin. `scripts/build-quic-helper.sh` prepares
a Mac component for a future candidate; Windows candidate assembly builds the
x64 helper and binds it to the runtime manifest. Neither command installs it.

Upstream source/provenance: UPSTREAM.json. Upstream GPL-3.0-or-later licensing is
preserved; this wrapper is GPL-3.0-only under the repository LICENSE. Source and
locked dependencies must accompany distributions under their respective terms.
