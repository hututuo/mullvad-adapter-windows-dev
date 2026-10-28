# Requirements

- AC-1: WHEN any saved account is chosen for management, THEN refresh/list/revoke/create are scoped to that account without changing template, selected city or live worker. Input login remains visible even with a saved login. Full device capacity does not prevent listing or confirmed removal.
- AC-2: WHEN a refresh fails or expires, THEN retain old official data with its original timestamp and an explicit stale/error state. A busy local read must never combine one account's list with another's freshness.
- AC-3: WHEN a fresh official list lacks a previously registered current identity, THEN show an actionable device-registration warning and suppress repeated tunnel recovery; absence under an unrelated account is not revocation.
- AC-4: WHEN a user creates a new device, THEN persist its key before submission, reconcile unknown outcomes without replay, and require exact official receipt/address/key binding before saving. Saving never activates; explicit activation serially stops the old peer before committing.
- AC-5: WHEN control API discovery fails, THEN report API route failure separately from device absence/tunnel failure; never weaken TLS, leak credentials to argv/logs, use the adapter's own front as bootstrap, or automatically replay a device mutation.
- AC-6: WHEN Stop is clicked during recovery/switching, THEN reject new data work and attempt all owned cleanup. Only confirmed cleanup plus persisted stop can report success. Keep account management accessible and pause background remote work. Old tickets cannot resume it.
- AC-7: WHEN a user requests removal of the current local device, THEN preserve default protection unless all connections are confirmed stopped and the user explicitly confirms that device.
- AC-8: WHEN a DELETE succeeds but trailing list refresh fails, THEN report confirmed deletion with an unverified list, not a failed deletion requiring replay.

Validation is synthetic/local unless separately recorded; source tests never imply installed or live-account acceptance.
