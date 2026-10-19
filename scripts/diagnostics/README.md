# Tunnel component diagnostic

`test-tunnel-path.ps1` tests direct WireGuard, WG-over-SS, or WG through an independent local Clash SOCKS endpoint without rebuilding the application. It does not change system routes, TUN, account/device registration, or Clash configuration. Run serially from a persistent Windows PowerShell session; a failed cleanup intentionally retains the peer lease.

This is a maintenance harness, not a user onboarding command. It requires trusted local IPC helpers (`Invoke-AdapterCommand` and legacy `Invoke-FriendClash`), an existing DPAPI identity blob, a verified public-device receipt, the installed pinned engine, current relay catalogue, and `synthetic-ss-template.json` in the diagnostic directory. Identity inputs remain local and must never be committed or copied into an issue. See mandatory script parameters.

The adapter must already be idle with its front rejecting traffic and the official VPN disconnected. The harness verifies identity, process/listener ownership and the independent Clash selection before use. `clash` requires an independent selected provider with UDP support on local SOCKS port 7897; it rejects a route back to Mullvad.

A component pass requires both literal-IP and hostname HTTPS probes. `-ExitCheck` additionally records the Mullvad exit verdict. Such results do not establish product integration, bound-carrier acceptance, long-term stability, or installer acceptance.
