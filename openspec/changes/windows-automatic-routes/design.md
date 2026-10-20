# Design

`CatalogueRefresh` supplies startup/24h/60s-300s-900s scheduling and a shared
manual/automatic reservation. A separate anonymous GET worker validates official
metadata and atomically replaces a versioned cache with its fetched timestamp.
It reads the API address cache and keeps account session/mutation ownership in
the existing account lane. Completed metadata applies between candidate/ICMP
operations without cancelling a healthy worker or renewing recovery budgets.

Startup queues one cancellable connection intent after IPC dispatch, behind
account/candidate/ICMP occupancy and the existing physical settling gate. The
last-path DPAPI receipt supplies only reauthorized preferences; it never restores
traffic without the normal startup transaction and canaries.

The native Clash reader exposes names/digests only. On explicit import it rereads
one flat compatible SS leaf, checks its displayed digest and sends credentials
through authorized IPC into a dedicated DPAPI record. Runtime generation keeps
WG -> Mullvad SS -> imported SS -> authenticated owned UDP carrier. Only the
imported leaf's resolved public IPv4/port is the physical socket destination.
Direct and chained measurements share existing per-relay/global/time bounds.
An active/retained chain cannot change its imported upstream in the background.

No external proxy-group mutation or generic SOCKS endpoint is trusted as the
carrier's physical witness. First support is IPv4 UDP standard SS without plugins;
provider path/transform restrictions are explicit. Import is a local snapshot,
not an automatic refresh of the user's third-party subscription.
