# Design

ObservedOwner tracks monotonic stable-since separately from evidence freshness. Notifications, gaps and binding changes clear/reset it; cancellation remains immediate. Product Connections and queued user connections wait for the same binding for SETTLE_MS before new work. No sleeps/locks on the owner.

ResourceOwner classifies a binding-invalidated operation only for its exact ticket and still-owned intent: a physical-offline epoch change may retain intent, but user/identity operation or generation changes may not. On clean stop a still-current automatic candidate is deferred without consuming the next relay or extending the recovery budget. Explicit relay selection gets a bounded, empty-alternative manual retry queue; preemption/disconnect clears it. User actions accepted while settling remain queued and cancellable.

Direct control-plane transport uses an authority-restricted custom resolver with Mullvad 2026.5's official API seed. HTTPS authority and certificate verification stay unchanged. Explicit proxy uses its own resolver/routing; never fall back from it, and never replay mutations. TLS-verified official api-addrs results are bounded and DPAPI-cached; only successful direct connections update last_success. Credential-free discovery chooses direct, an explicitly configured independent proxy, then an already healthy front within a bounded budget. Account mutations are sent once after route selection, never replayed. UDP-over-TCP/QUIC remain separate work.

The packaging prerequisite includes explicit nested weak Task capture for Xcode 15.4 compatibility; no Mac window/runtime behavior change is intended.

The generated independent Clash profile routes the literal API seed through the same independent account/catalogue group as the API domain, before business MATCH rules. This prevents TUN bootstrap recursion; existing profiles must be regenerated/selected to receive it.

Healthy worker assessment distinguishes Bound (including partial DNS/service degradation), fresh sent-but-unready negative path evidence, local measurement failure, cancellation, and physical binding change. Local failures get a short same-worker recheck; two consecutive local failures rebuild the original path without attributing node failure, covering same-interface DHCP/route changes. Candidate negative evidence that expires is requeued on the same relay without consuming the backup queue.
