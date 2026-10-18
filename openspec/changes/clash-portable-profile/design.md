# Design and boundaries

- Versioned routing policy derives from the existing Mac rule ordering. Drive
  exceptions precede broader Google/AI matches. Remove personal paths, interface
  bindings and public-IP exceptions. These are policy rules, not API node facts.
- Official relay API supplies relay addresses/public keys/SS endpoints and port
  ranges; local device keys are generated locally. SS protocol constants differ
  from personal credentials. ICMP/advertised capabilities are not readiness.
- Build profile natively; renderer sees names/counts/selection/hash, never node
  credentials or subscription URLs. Reuse independent concrete nodes and HTTPS
  HTTP providers with isolated cache paths. Report excluded chains/file sources.
- An independent account/API group excludes the adapter. Default DIRECT uses OS
  routing; an existing independent node may be selected. No automatic replay or
  secret fallback when direct API fails. External TUN rules remain part of the
  explicit route contract, not a claim that direct HTTPS binds a physical NIC.
- Verge v2.5.8 publicly supports clash://install-config?url=..., not an external
  local-profile creation API. Use a durable loopback-only subscription service
  with an owner-private random capability, stable port across tray restarts,
  immutable content hashes, strict Host/path checks and no Origin/CORS access.
  No one-shot URL, internal index mutation or UI-IPC bypass. Closing the window
  hides to tray; exiting UI stops subscription refresh but cached Clash traffic
  and per-provider refresh continue. Reopening restores the same service URL.
- Official import preserves an existing selected profile; when empty, Verge may
  select the first imported profile itself. Therefore import requires a ready
  tunnel, while export/preview are available disconnected. Never auto-select via
  Mihomo API. Launch acknowledgement, index/file readback, selection, live route,
  and actual egress are separate evidence levels.
  The native one-click action waits up to 20 seconds for the client's own import
  and byte readback. Timeout retains the saved profile and an unconfirmed state;
  it never asks the user to perform a second manual file import.
- Known Tailscale/UU process names and Tailscale control domains precede business
  rules in an independent remote-control group (DIRECT by default, eligible
  existing concrete proxies only). Retain multicast REJECT, but do not blindly
  copy broad Mac port-based DIRECT exceptions or personal process paths.
- Existing Clash geodata remains a client prerequisite for CN GEOIP/GEOSITE;
  pinned-engine validation may fail if those files cannot be obtained. Do not
  report a candidate/import success if validation fails.
- WG keepalive=25s maintains idle mappings; it does not bypass UDP blocking. SS
  remains UDP in this product. QUIC/UDP-over-TCP/LWO/multihop/PQ are not silently
  substituted or declared working. Same-city/physical-network recovery policy
  remains unchanged. Failed active Verify schedules a 15s retry floor.
