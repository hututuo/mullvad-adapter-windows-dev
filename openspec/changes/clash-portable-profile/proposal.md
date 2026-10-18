# Independent portable Clash profile

Create a separate complete profile instead of requiring a selected subscription,
a private extension script and an existing ordinary node. AI and ordinary exits
both default to the local Mullvad ingress and may independently select imported
user nodes. LAN/domestic routing stays DIRECT. Preserve legacy integration undo.

Audit data provenance and restrictive-network behavior alongside this change:
explicit direct HTTPS control-plane access without a pre-existing proxy, NAT
keepalive, bounded failed-health retries, and honest unsupported transports.
