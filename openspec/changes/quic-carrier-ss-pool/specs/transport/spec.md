# Transport requirements

- SS-1: Official extra addresses combined with all advertised SS ports for ranges
  of at most512 unique ports must be selectable and exact-path re-authorizable.
  Larger ranges use a deterministic bounded sample. Existing dedicated ports,
  small attempt windows and history/epoch semantics remain compatible.
- Q-1: QUIC address/domain/token come from the current official relay directory.
  Port443 and the inner target127.0.0.1:51820 are pinned protocol constants.
  Invalid QUIC metadata disables QUIC without discarding a usable SS relay.
- Q-2: The carrier injects a verified interface-bound socket into the pinned
  official MASQUE client. It never routes by the default TUN or disables TLS
  validation. Required bindings fail closed. Local UDP endpoints are loopback.
- Q-3: Carrier TLS/HTTP3 ready is separate from WireGuard/data readiness. Full
  canaries, current physical route, epoch and owned process must still agree.
  Packet observations never assert cryptographic handshake authentication.
- Q-4: Stop, cancellation, helper death and failed startup clean up owned helpers
  and workers. Uncertain cleanup retains ownership; no duplicate live peer.
- Q-5: Automatic recovery retains original-path short retries, SS candidates and
  same-city boundaries, then QUIC, native IPv6/IPv4 and finally optional chain.
  Missing local components do not poison remote relay/SS history.
- Q-6: Token/key material does not enter argv, ordinary logs, Debug, reports or
  generated Mihomo configuration. Status reads use cached local observations.
- Q-7: Legacy runtime packages work with QUIC unavailable. New packages bind the
  optional helper to manifest hashes; tests do not imply installation/egress.

Acceptance uses synthetic fixtures and pinned-core parsing. Actual Mac/Windows
QUIC egress, TUN routing and natural recovery are independent live gates.
