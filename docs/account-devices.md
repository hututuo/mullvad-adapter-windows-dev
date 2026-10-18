# Account and device management

The SwiftUI Account & Devices page calls the adapter's `/account` API using a random capability stored in the user's private state directory. Every account endpoint, including private-key viewing, requires this capability; browser-origin requests are rejected. Responses are not cacheable. The page is compatible with a legacy daemon by showing that the paired backend upgrade is required, while existing city/tunnel controls remain available.

The Ruby adapter independently implements the REST contracts studied in Mullvad's official open-source client:

- [Token acquisition and caching](https://github.com/mullvad/mullvadvpn-app/blob/main/mullvad-api/src/access.rs).
- [Account expiry and voucher redemption](https://github.com/mullvad/mullvadvpn-app/blob/main/mullvad-api/src/lib.rs).
- [Device listing, removal and key registration contracts](https://github.com/mullvad/mullvadvpn-app/blob/main/mullvad-api/src/device.rs).
- [Official architecture](https://github.com/mullvad/mullvadvpn-app/blob/main/docs/architecture.md).

No upstream implementation was copied. The official application's source is GPL-3.0-or-later; studying API contracts does not integrate or redistribute its VPN daemon.

## Supported operations

| Action | Behavior |
| --- | --- |
| Verify account | Normalize the 16-digit account, fetch a token, account expiry and devices; save the account only after successful validation. Failed replacement login retains previous credentials. |
| Device identity | Derive the current template's public key using RFC 7748 base-point multiplication and compare exact public keys against the official list. Device names are supplied by the API, not invented from the machine hostname. |
| Refresh | Fetch official account/device state; display the verification timestamp separately from the adapter's live tunnel state. Saved login is revalidated when first opening the page after a daemon restart. |
| View key | Show the current local private key only after explicit confirmation. Hide after 20 seconds, on leaving the page or losing app focus, including late reveal responses. No automatic private-key clipboard copy or diagnostic export. |
| Create local device | Require confirmation; durably save the local key before POST, validate the returned ID/key/assigned addresses, and retain unknown outcomes without blind retries. A previously retained draft is not overwritten. |
| Remove another device | Require confirmation, refresh the official list immediately before deletion and reject removal of the adapter's current public-key identity. Never retry an ambiguous network failure automatically. |
| Voucher | Confirm the destination account suffix, redeem using the official API, then refresh expiry. If the result is uncertain, refresh before resubmitting. |
| Clear login | Remove local account credentials and in-memory tokens; preserve the original WireGuard template and existing tunnel. The product labels this as exiting account management, not network disconnection. |
| Reconnect | Use the existing adapter operation for the current node; city recovery policy remains in effect. |
| Purchase/account website | Open the generic official account page without placing credentials in a URL or automatic browser login. |

The account number is itself a credential. It is stored only in an atomic 0600 file within a 0700 state directory. Tokens stay in memory. Authenticated curl requests read account/token/voucher data from stdin, not process arguments or environment. Network requests follow the same configured local bootstrap proxy as metadata refresh; API outages do not change tunnel state. An account action has a separate nonblocking gate and does not hold the switching mutex. Neither account/device identifiers nor authenticated response bodies enter events or diagnostic reports.

## Identity and official VPN boundaries

An account can validate successfully while the current public key is absent from its device list. The UI reports this as an unmatched account, never as a connected device. Both frontends support explicitly creating a device under an existing account. They generate X25519 locally and save the pending private key before registering only its public key. Mac stores new-device drafts in the non-synchronizing local Keychain; Windows stores them in a DPAPI record bound to the full account fingerprint. A submitted or unknown result survives restart and prevents automatic resubmission. Other devices' private keys cannot be downloaded from Mullvad.

Windows may explicitly activate the newly created local device only after the front has confirmed REJECT and connection I/O has drained. The previous identity is preserved and read back in DPAPI before replacement. A different valid older backup is first archived as its exact encrypted bytes, under the same owner-only access rules; an invalid, conflicting or unsafe archive blocks replacement. A fresh connection must pass the normal tunnel tests. Mac currently creates a local backup device and can explicitly view its Keychain-held key; this does not automatically replace the current template. Neither frontend creates a new Mullvad account. The Rust API also provides typed public-key replacement, but the product does not automatically rotate a live device's key.

After Windows has activated a completed draft, a subsequent confirmed device creation may use the same or a different account. It first verifies that the durable active public key matches the completed draft, then archives that draft's original DPAPI ciphertext before preparing a new key. A created draft awaiting activation remains reusable on its original account. Prepared, submitted and unknown drafts cannot be discarded across accounts, and uncertain registrations are never blindly resubmitted. Archived records are not automatically restored or deleted; the storage layer provides validated, read-only recovery by record kind and ciphertext SHA256. Login and logout alone never trigger this replacement flow.

The official app's system firewall, TUN, split tunneling, DAITA, multihop and automatic key rotation are not plain account API controls. Multihop now has a separate adapter data-path implementation; see `tunnel-protection.md`. Other capabilities require their own supported engine/identity integration and cannot be represented as working account switches. The existing project controls its own city/transport/recovery and leaves the system ingress to Clash. Creating those features requires a separate supported data path, not copying the official UI.

Current tests use controlled official API responses and published RFC 7748 vectors. Compilation or mocks do not prove a real account login, voucher redemption, device revocation, production installation or an identity upgrade. Do not mutate the user's real account as a test.

## Windows account boundary

The ordinary-user Rust host exposes account commands over the user/session-bound named pipe. Tokens stay in RAM. Device listing also works before an identity is configured; every row is then marked as another device rather than fabricating a current-device match. Secret key-view replies are explicitly requested and excluded from public status, diagnostic reports and replay receipt caches. All official API calls use the configured local bootstrap proxy with verified TLS and redirects disabled. API availability is separate from the current tunnel's availability.
