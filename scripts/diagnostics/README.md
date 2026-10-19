# Tunnel component diagnostic

`test-tunnel-path.ps1` tests direct WireGuard, WG-over-SS, or WG through an independent local Clash SOCKS endpoint without rebuilding the application. It does not change system routes, TUN, account/device registration, or Clash configuration. Run serially from a persistent Windows PowerShell session; a failed cleanup intentionally retains the peer lease.

This is a maintenance harness, not a user onboarding command. It requires trusted local IPC helpers (`Invoke-AdapterCommand` and legacy `Invoke-FriendClash`), an existing DPAPI identity blob, a verified public-device receipt, the installed pinned engine, current relay catalogue, and `synthetic-ss-template.json` in the diagnostic directory. Identity inputs remain local and must never be committed or copied into an issue. See mandatory script parameters.

The adapter must already be idle with its front rejecting traffic and the official VPN disconnected. The harness verifies identity, process/listener ownership and the independent Clash selection before use. `clash` requires an independent selected provider with UDP support on local SOCKS port 7897; it rejects a route back to Mullvad.

A component pass requires both literal-IP and hostname HTTPS probes. `-ExitCheck` additionally records the Mullvad exit verdict. Such results do not establish product integration, bound-carrier acceptance, long-term stability, or installer acceptance.

`-SsExtraIndex` selects an existing official SS extra IPv4 address by index; it cannot introduce an arbitrary endpoint. `-ObserveWire` is direct-WG-only and requires the matching `udp-wire-observer.cs` in the diagnostic directory (or `-WireObserverPath`). The observer forwards encrypted WG datagrams through a source/interface-bound UDP socket and reports counts, sizes and conservative WG/DNS envelope shapes. Shape is neither authentication nor proof of packet origin; the engine still verifies WG. It never promotes a component result to a product `BoundReport`. Both engine and observer must stop before the peer lease is released.

`test-direct-tcp.ps1` performs serial, three-second TCP-connect probes to active official relay primary IPv4 addresses, binds the selected physical interface/source and rechecks the route afterward. Defaults use the San Jose relays and official UDP-over-TCP fallback ports 80, 443, 5001; override `-Relay`, `-Port` and `-CatalogPath` explicitly when needed (at most 48 cases). A TCP connection is only endpoint reachability and does not prove the obfuscation protocol or WG tunnel.
