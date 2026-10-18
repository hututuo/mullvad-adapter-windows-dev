# Windows network-change hints

NetworkChanges registers NotifyIpInterfaceChange, NotifyUnicastIpAddressChange and NotifyRouteChange2
with AF_UNSPEC and InitialNotification=false. The callback context is an owned
Arc<AtomicU64>. Each callback only performs a saturating Release increment; no
allocation, locks, I/O, domain state access, or row dereference occurs. Rows are
incomplete, OS-owned hints, so the state owner's sampling worker still reads full
tables. This registration does not change interfaces, addresses, routes or DNS.

Each successful registration retains one strong reference until successful
CancelMibChangeNotify2 completion. Registration failure returns its Windows error
and releases the unregistered reference. Partial setup drops all earlier leases.
Cancellation runs outside callbacks and holds no resource a callback needs.
NetworkChanges is movable to the sampling worker: its Drop never belongs to the
responsive owner loop. A blocked sampler delays worker teardown and cancellation;
no hard cancellation or teardown deadline is claimed.

Explicit close attempts all three cancellations and returns an error if any fails.
Drop retries any still-active handle. If final cancellation fails, the retained
callback allocation is deliberately leaked until process termination, avoiding
use-after-free. No successful cleanup is claimed on that exceptional path. The
agent creates one registration set per owner lifetime, not one per sample.
Repeated owner reconstruction after cancellation failure has no process-wide
leak bound. Registration or thread-spawn failure can synchronously cancel during
construction; only dropping an already returned owner has the nonblocking lease
placement described above.

Three Windows tests cover concurrent direct invocation of the callback routines
and counter saturation, actual registration/explicit idempotent close releasing
three strong references, and actual registration moved to and dropped on a worker.
The control tests separately prove that dropping an owner does not release its
worker-owned lease before a blocked sample returns. These tests do not induce a
real NIC change or prove Windows delivered a particular physical-change event.
Registration failure, cancellation failure and in-flight callback rundown are
currently code-reviewed paths, not fault-injected test evidence.

Sources:
- [Interface registration](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyipinterfacechange)
- [Address registration](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyunicastipaddresschange)
- [Cancellation and callback deadlock constraints](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-cancelmibchangenotify2)

- [Route-change registration](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyroutechange2)
