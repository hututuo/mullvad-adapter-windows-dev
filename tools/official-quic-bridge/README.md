# Official QUIC diagnostic bridge

This isolated Windows-only test tool links the official Mullvad MASQUE client at commit `19fb87407f4b81fe15372c2c7f8a20e7ab4eb220`. It accepts capped JSON on stdin, binds a caller-selected physical IPv4 source/interface, and exposes only a loopback UDP socket. It neither handles a WireGuard private key nor changes routes, TUN, system proxy or account/device state. Input domain/token must come from the chosen active relay official QUIC metadata. Keep input local; never put tokens in arguments, CI, issues or logs.

The tool supplies its own strict TLS 1.3 Web-PKI verifier and h3 ALPN. It does not use upstream's permissive default verifier or the example TLS key logger. Compatibility with actual relay certificates is NOT_RUN until tested; certificate incompatibility must not be reported as a transport timeout. The inner WG engine remains independently authenticated.

A `bridge_ready` line means QUIC/HTTP3 CONNECT-UDP completed, not a working VPN. Only a separate real WG IP/hostname/official-exit test can establish tunnel connectivity. Parent tooling must hold the peer lease until both WG engine and this exact bridge process are confirmed stopped. Connection setup is capped at 15 seconds, bridge lifetime at 90 seconds. This is not an integrated product feature or installer.

The official dependency is GPL-3.0-or-later; this wrapper chooses GPL-3.0-only for compatible combined use. Official source and license: https://github.com/mullvad/mullvadvpn-app/tree/19fb87407f4b81fe15372c2c7f8a20e7ab4eb220 . Preserve Cargo.lock and the pinned source reference with diagnostic artifacts.
