# Design

ObservedOwner tracks monotonic stable-since separately from evidence freshness. Notifications, gaps and binding changes clear/reset it; cancellation remains immediate. Product Connections and queued user connections wait for the same binding for SETTLE_MS before new work. No sleeps/locks on the owner.

ResourceOwner classifies a binding-invalidated operation only for its exact ticket and still-owned intent: a physical-offline epoch change may retain intent, but user/identity operation or generation changes may not. On clean stop a still-current automatic candidate is deferred without consuming the next relay or extending the recovery budget. Explicit relay selection gets a bounded, empty-alternative manual retry queue; preemption/disconnect clears it. User actions accepted while settling remain queued and cancellable.

Direct control-plane transport uses an authority-restricted custom resolver with Mullvad 2026.5's official API seed. HTTPS authority and certificate verification stay unchanged. Explicit proxy uses its own resolver/routing; never fall back from it, and never replay mutations. Dynamic official API address cache and UDP-over-TCP/QUIC remain separate work.

The packaging prerequisite includes explicit nested weak Task capture for Xcode 15.4 compatibility; no Mac window/runtime behavior change is intended.

The generated independent Clash profile routes the literal API seed through the same independent account/catalogue group as the API domain, before business MATCH rules. This prevents TUN bootstrap recursion; existing profiles must be regenerated/selected to receive it.
