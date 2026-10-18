# Added requirements

## PP-01 Empty and populated client
Generation SHALL work with no selected profile or nodes. With existing data it
SHALL create an independent profile without modifying current profile/index,
existing provider caches, scripts or selection. AI and ordinary selectors SHALL
default Mullvad, and independently allow eligible user nodes/providers. Domestic
and LAN rules SHALL stay direct, Drive ordinary exceptions precede AI matches.

## PP-02 Secret boundary and control-plane independence
The renderer SHALL receive only allowlisted summaries. API routing SHALL never
select the adapter or a group with an implicit adapter fallback. No optional
bootstrap proxy SHALL mean explicit HTTPS over system routing with environment
proxy disabled; configured proxy failure SHALL NOT silently fall back/replay.

## PP-03 Durable official import and truthful status
Imports SHALL use official protocol support and a durable owner-private local
subscription. They SHALL NOT rewrite profiles.yaml or use a disposable download
URL. Preview hash drift blocks writes/import. Import launch does not establish
registration or egress. Readback SHALL require matching URL and immutable bytes.
First import may be selected by Verge; disconnected imports SHALL be blocked.
The single import action SHALL wait for bounded registration readback and report
an unconfirmed dispatch honestly. A user SHALL NOT need to select a file or
paste a subscription URL in the external client. Existing-profile activation
remains an explicit user choice.

## PP-05 Remote access independence
Known Tailscale and UU process names and Tailscale control domains SHALL precede
business routing and use a separate selector excluding the adapter. DIRECT is
the default; an independent existing node may be selected in Clash. Personal
process paths and physical-interface bindings SHALL NOT be copied. Portable
multicast rejection SHALL be retained. Unknown processes and physical route
behavior require separate runtime verification.

## PP-04 NAT and recovery limits
Both engines SHALL use explicit 25-second WireGuard keepalive. Failed active
health verification SHALL NOT requeue full checks every host tick when recovery
is disabled/unavailable. Physical disconnect SHALL remain paused; resume SHALL
verify original path first, and alternatives SHALL remain in the chosen city.
Unsupported anti-censorship transports SHALL remain explicit limitations.
