# Design

`helpers/quic-carrier` links the official2026.5 `mullvad-masque-proxy` at the
existing pinned upstream SHA. The adapter supplies physical interface/source,
and keeps one bounded stdin/stdout process lease per worker. TLS/H3 CONNECT must
finish before the carrier emits ready; WG IP/DNS/HTTPS validation follows.

A counted loopback UDP bridge exposes packet observations without device keys.
Only explicit stats commands produce counter replies, avoiding output buildup.
Parent EOF terminates the carrier; native Windows Job ownership also fences
children. Mac workers retain carrier ownership across PQ's serial core rebuild.

QUIC is an additional direct carrier, not an SS or Hysteria/TUIC parameter.
Alternative UDP-over-TCP/LWO remain explicitly unavailable. Future carriers can
reuse the process/binding contract; they require independent implementation and
acceptance. This change does not claim universal UDP reachability.
