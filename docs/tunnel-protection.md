# Tunnel protection and official feature mapping

The adapter keeps Clash as the system ingress. A working account REST call does not activate VPN data-plane features. The Protection page separates the committed policy from the active worker and reports unavailable capabilities without enable switches.

## Implemented multihop

A circuit uses two separate Mihomo WireGuard outbounds: EXIT sends its UDP transport through WG-ENTRY. The entry may itself use the existing SS inlet or direct IPv4/IPv6 transport. Entry AllowedIPs is only the exit's relay IPv4 address /32; the exit uses the configured tunnel identity and default payload routes. The exit endpoint is the relay's IPv4 address on port 51820, as specified by the official stable relay selector, not a guessed or missing metadata field. Entry and exit must be distinct peers. The entry has no remote DNS resolver; the exit resolves through Mullvad's inner DNS. The initial conservative exit MTU is 1200.

The selected exit city and same-city automatic recovery boundary remain unchanged. An independently selected entry city supplies at most two candidate relays and two SS inlets per relay, within existing attempt budgets. Each candidate reserves both entry and exit server keys; a live entry cannot be reused by another independent worker. An unavailable entry never produces a single-hop substitute. No constant hot standby is created.

`GET /protection` reports committed profile, active path, capability reasons and observation time. `POST /protection` requires the existing local capability and rejects browser Origin requests. It returns an operation receipt. Changing protection on the current exit rebuilds that peer without overlap, validates IP/DNS/HTTPS and atomically saves the policy only after readiness. A failed change rebuilds the old policy; a corrupt saved policy blocks new tunnels until an explicit valid change. Configuration-write failures reach rollback. The ordinary front, drain and probe-generation invariants remain in force.

Multihop probe events include entry and exit identity. They do not update single-hop history or make backup nodes look verified using evidence from a different circuit. Multihop backup candidates therefore remain unverified until their complete circuit is checked.

### Policy transaction commit boundary

Every newly negotiated PQ worker, including a rollback worker, must pass the same complete readiness gate before front selection. Preserving an existing non-PQ data path with degraded DNS remains a separate policy and does not weaken that gate.

A changed protection profile is written and fsynced to a unique pending file first. The final network-epoch check and rename to `protection.json` share the state mutex with the network observer. An outage before that commit point rejects the candidate and leaves both the saved and in-memory committed profile unchanged. An outage after that point is a new outage against the newly committed policy. Preparation cleanup runs on ordinary failure; startup ignores pending files left by an abrupt process death and reads only `protection.json`. A process crash after the commit rename recovers the new committed profile. These process-interruption guarantees do not claim power-loss durability or Windows filesystem acceptance.

Controlled regression coverage is in `daemon/test_protection_transactions.rb`: degraded PQ rollback, accepted ready rollback, interrupted PQ enable/disable, final rename failure, and process death on each side of the policy commit point. It uses fake engines and injected observations, not live tunnel acceptance.

## Implemented single-hop post-quantum negotiation

The candidate packages `mullvad-pq-negotiator`, linked to the official stable config client. The daemon establishes an isolated bootstrap worker under the persistent device identity, performs ML-KEM-1024 and HQC-256 negotiation over that worker's loopback SOCKS route to the in-tunnel configuration service, and restarts the candidate using the returned ephemeral identity and PSK. Private identity/PSK values travel only on pipes and an owner-only transient runtime configuration; that configuration is removed once the final core has loaded it. The persistent template/account identity is unchanged. Final IP/DNS/HTTPS readiness is required before front selection. A missing helper is rejected before stopping an old peer. Failed negotiation cleans up the bootstrap and cannot silently turn PQ off. Public state exposes only negotiated status and helper SHA256.

Single-hop PQ has passed isolated real egress checks. The multi-hop combination is explicitly rejected by both backend preflight and UI: experimental runs have mixed final-tunnel results and are not a supported feature. Ordinary multihop and single-hop PQ remain independent usable modes. PQ observations do not populate ordinary single-hop recovery history.

## Feature inventory

| Official capability | Mechanism | Adapter status / required component |
| --- | --- | --- |
| Multihop | Nested entry and exit WireGuard devices | Implemented with explicit Mihomo dialer chain |
| Shadowsocks obfuscation | Wrap outer WG datagrams in SS | Existing SS transport, usable as multihop carrier |
| Quantum-resistant tunnel | In-tunnel ML-KEM/HQC key exchange, fresh ephemeral WG identity and PSK | Implemented for single-hop with the packaged official config-client helper; combined multihop/PQ is gated pending reliable acceptance |
| DAITA | Negotiated Maybenot machines plus tunnel engine padding, delays and decoy generation | Stock Mihomo lacks GotaTun DAITA data-plane hooks; needs engine integration |
| UDP-over-TCP | Dedicated adapter wraps outer datagrams over TCP | Needs packaged official carrier, interface-bound outbound sockets and endpoint mapping |
| QUIC obfuscation | Dedicated QUIC carrier for outer datagrams | Needs packaged official carrier, interface-bound outbound sockets and endpoint mapping |
| LWO | Lightweight WG obfuscation supported by compatible relay/device | Official obfuscation carrier needs socket routing integration; AmneziaWG options are not a substitute |
| Lockdown, split tunnelling, system DNS/firewall | Official OS tunnel state machine | System ingress remains owned by Clash; not account controls |
| New device/key rotation | Register identity, allocate addresses and atomically migrate tunnel state | Separate identity transaction, not performed by protection settings |

Post-quantum encryption protects key agreement; transport obfuscation resists protocol recognition; DAITA addresses traffic analysis. One does not imply the others. A static PSK alone is not official post-quantum negotiation.

## Stable upstream references

Research baseline is desktop tag 2026.5, full SHA `19fb87407f4b81fe15372c2c7f8a20e7ab4eb220`. Current main was also compared; it refactors negotiation and is not a drop-in API replacement.

- [Official multihop relay construction](https://github.com/mullvad/mullvadvpn-app/blob/2026.5/mullvad-relay-selector/src/relay_selector/detailer.rs).
- [Official userspace devices and DAITA](https://github.com/mullvad/mullvadvpn-app/blob/2026.5/talpid-wireguard/src/gotatun/mod.rs).
- [Official PQ configuration client](https://github.com/mullvad/mullvadvpn-app/blob/2026.5/talpid-tunnel-config-client/src/lib.rs) and [protocol](https://github.com/mullvad/mullvadvpn-app/blob/2026.5/talpid-tunnel-config-client/proto/ephemeralpeer.proto).
- [Official architecture](https://github.com/mullvad/mullvadvpn-app/blob/2026.5/docs/architecture.md).
- [Mihomo WireGuard configuration](https://wiki.metacubex.one/en/config/proxies/wg/) and [v1.19.31 implementation](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/wireguard.go).

## Acceptance boundary

Generated configurations and transaction tests do not prove live tunnels. Current engineering acceptance includes a separately owned SS multihop circuit and official exit verification, plus single-hop PQ final IP/DNS/HTTPS readiness and official exit verification. Production installation, interruption timing, IPv6 outer reachability, DAITA and combined multihop/PQ are separate gates. Preserve those gates separately in private verification records.

## Remaining carrier and engine work

The official `tunnel-obfuscation` factory can supply a local UDP endpoint for UDP-over-TCP, QUIC or LWO. Its remote sockets do not implement the adapter's existing SS dialer or macOS physical-interface binding. Starting those helpers with default system routing may send their own transport back through Clash into this adapter; they are not enabled until that routing boundary is implemented and tested. QUIC address/domain/token come from relay `features.quic`; port 443 is an official protocol constant. LWO uses relay feature advertisement and WG port ranges. UDP2TCP ports 80/443/5001 are the official client's compatibility defaults when the relay API omits the field; they must not be presented as API observations.

DAITA additionally requires the compatible GotaTun/Maybenot data plane to execute negotiated machines and produce padding/decoy traffic. Stock Mihomo WireGuard cannot perform this by changing JSON options. Replacing the data plane requires a dedicated local packet/SOCKS bridge and the current front, city recovery, socket routing and key lifecycle invariants; activating the official system VPN daemon would interfere with the existing Clash ingress.
