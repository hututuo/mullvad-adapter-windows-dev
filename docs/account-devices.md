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
| Reconcile registration | Explicitly fetch the official account and device list and match the retained local public key. Preserve the original private key and mark registration confirmed; do not repeat POST, infer assigned addresses or activate the identity. |
| First Mac identity install | Require an address-bearing created draft, exact account/device/key binding, durable official registration receipt, fresh official ownership match and no existing identity or running engines. Atomically commit an owner-only template and report identity configured; city connection and readiness remain separate. |
| Abandon unfinished Mac install | Explicitly archive and release only an uncommitted local installation. Bind the current account, original account and expected metadata hash; preserve original metadata, any pending template and the official device. A backend completion receipt permits archiving that account's old Keychain draft before a later explicit Create. |
| Remove another device | Require confirmation, refresh the official list immediately before deletion and reject removal of the adapter's current public-key identity. Never retry an ambiguous network failure automatically. |
| Voucher | Confirm the destination account suffix, redeem using the official API, then refresh expiry. If the result is uncertain, refresh before resubmitting. |
| Clear login | Remove local account credentials and in-memory tokens; preserve the original WireGuard template and existing tunnel. The product labels this as exiting account management, not network disconnection. |
| Reconnect | Use the existing adapter operation for the current node; city recovery policy remains in effect. |
| Purchase/account website | Open the generic official account page without placing credentials in a URL or automatic browser login. |

The account number is itself a credential. It is stored only in an atomic 0600 file within a 0700 state directory. Tokens stay in memory. Authenticated curl requests read account/token/voucher data from stdin, not process arguments or environment. Account control access is independent of the WireGuard key and tunnel; it never sends a device private key to authenticate account management. Metadata retains its separate existing route policy. Mac now performs credential-free API-address discovery to choose an independent route before sending account credentials: recent verified direct address, configured loopback bootstrap, official seed/cached addresses and system HTTPS, all bounded with TLS hostname/SNI preserved. The selected route stays fixed during the transaction. There is no automatic replay of failed or uncertain device actions. API outages do not change tunnel state. An account action has a separate nonblocking gate and does not hold the switching mutex. Create, revoke, voucher and logout requests must include the full-account fingerprint returned by the authorized snapshot; a stale or missing binding fails before official API access. Neither account/device identifiers nor authenticated response bodies enter events or diagnostic reports.

## Mac first-run and retained drafts

Without an existing WireGuard template or an explicitly supplied import profile,
the Mac daemon exposes account management in `needs_setup` state. It starts no
front, workers, metadata refresh or recovery monitors. Other control mutations
are rejected. Login and device lists work without a tunnel identity; no listed
device is called current. An explicit invalid profile fails instead of importing
another profile. First identity installation is an explicit separate operation;
restarting alone does not turn a Keychain draft into a tunnel template.

Clean state has no implicit historical Clash profile, relay or proxy listener.
An existing cached template preserves the historical local bootstrap listener and
relay fallback when no explicit launch option overrides them. The account page
labels this proxy as a legacy local default. These compatibility values are local
policy, never official API data. An owner-only `bootstrap-defaults.json` records
whether state originated with legacy or clean defaults; adding an identity later
cannot silently convert clean state to legacy defaults. Use `--bootstrap-proxy ''` to explicitly choose
system HTTPS, or supply a literal loopback HTTP proxy. This does not claim a
physical-interface bypass or guaranteed API access on a restricted network.

A submitted draft survives restart in the non-synchronizing local Keychain. The
page offers **核对官方登记结果** to match its public key against a fresh official
list. A match without a retained address-bearing official registration receipt
is saved as `registered`; the list contract does not provide assigned addresses.
If the local daemon durably retained the original official creation receipt, the
fresh matching list may recover that receipt as `created`. The original private
key is retained and no address is invented. A missing key, malformed list, changed
account, API failure or failed local save never reopens an uncertain registration
for automatic submission. An activated draft may be archived before another
explicit creation only while its account, device and public key still match the
daemon's installed-template receipt and fresh official current device. The exact
original Keychain bytes are copied to an immutable, non-synchronizing archive and
read back before generating a replacement draft; a cross-process owner-only writer
lock, archive conflict or readback failure prevents unsafe replacement. Prepared,
submitted and registered drafts cannot be discarded this way. An unactivated
created draft requires the separate, backend-confirmed abandonment below.
Direct live-template overwrites remain unavailable; the saved-profile path below supports explicit serial identity activation. See the
[Mac parity work list](mac-parity.md) for the remaining transactions.

The Mac install endpoint checks the retained official receipt against the full
account fingerprint, device ID, public key and both assigned addresses, then
derives the submitted local private key's public half and refreshes official
ownership. The account and switch locks cover engine-state checks, temporary
exclusive engine-listener reservations, installation receipt and no-replace
template commit. Local files/directories reject unexpected owners, public modes,
symlinks and hardlinks; a crash-created exact pending/target two-link pair is the
only hardlink recovery exception. Files and their parent directory are fsynced
where supported. A retry of an already completed installation must match the
fresh official identity, receipt and exact template bytes; it never replaces a
different template. Lost replies trigger readback, not replay. The template holds
only the local key and official tunnel addresses; relays/SS endpoints are still
selected from the normal official catalogue. Installation does not claim network
readiness and does not automatically select a new city. Actual Keychain, crash,
installation and egress acceptance remain distinct from mocked tests.

### Abandoning an unfinished local installation

The authorized snapshot exposes `pending_identity_installation` with the original
full-account fingerprint, device ID, public key, metadata SHA256 and cancellation
progress. It contains no private key or account credential. The explicit
`POST /account/identity/abandon` requires `confirm`, the current
`account_fingerprint`, `expected_installation_account_fingerprint` and
`expected_metadata_sha256`. This permits account B to release an unfinished
account A installation without changing either official account or device.
The endpoint requires no committed template and no engines; account/switch locks
and exclusive engine-port reservations cover archival and cleanup. A template
appearing during the operation stops cleanup.

Original metadata and any pending template are copied as exact private bytes to
fixed `retired-installations/<metadata SHA256>/` records and read back before a
durable cancellation plan permits cleanup. Each original inode, link count and
hash is checked again before unlink. A durable journal supports restarting after
any source removal. No official request, registration replay, revocation or key
restoration occurs. Canonical cancellation records use no-replace commits from
unique private staging files, so empty/partial writes never occupy their final
names. Only an exact two-link staging/target pair is recoverable; unknown links,
symlinks, unsafe ownership/modes, conflicting bytes or unexpected paths stop.
Records are limited to 16 KiB, with at most 64 installation archives, 64 account
indexes, 64 receipts per account and 64 staging files. Interrupted partial staging
files are retained, not silently deleted; capacity exhaustion stops safely.

`POST /account/identity/abandonment-status` is an authorized local read. It binds
the current account plus the original public key/device, optionally the original
account and metadata hash, and returns only a verified archive/completion proof.
A lost cancellation reply uses this read instead of resubmitting mutations. The
model marks a matching draft `abandoned` only with that backend proof; a subsequent
explicit Create verifies it again and archives the exact current Keychain bytes
before generating another key. An unfinished cancellation blocks that path and
new installation. Abandonment does not release an official device slot. The
archived identity is never automatically restored or reinstalled.

## Identity and official VPN boundaries

An account can validate successfully while the current public key is absent from its device list. The UI reports this as an unmatched account, never as a connected device. Both frontends support explicitly creating a device under an existing account. They generate X25519 locally and save the pending private key before registering only its public key. Mac stores new-device drafts in the non-synchronizing local Keychain; Windows stores them in a DPAPI record bound to the full account fingerprint. A submitted or unknown result survives restart and prevents automatic resubmission. Other devices' private keys cannot be downloaded from Mullvad.

Windows may explicitly activate the newly created local device only after the front has confirmed REJECT and connection I/O has drained. The previous identity is preserved and read back in DPAPI before replacement. A different valid older backup is first archived as its exact encrypted bytes, under the same owner-only access rules; an invalid, conflicting or unsafe archive blocks replacement. A fresh connection must pass the normal tunnel tests. Mac supports explicit first installation only when no prior template or engine exists; it can also retain a backup device without activation. It does not overwrite an existing running identity in place; a new address-bearing registration may now be saved as a separate Mac profile and explicitly activated after old worker cleanup. Neither frontend creates a new Mullvad account. The Rust API also provides typed public-key replacement, but the product does not automatically rotate a live device's key.

After Windows has activated a completed draft, a subsequent confirmed device creation may use the same or a different account. It first verifies that the durable active public key matches the completed draft, then archives that draft's original DPAPI ciphertext before preparing a new key. A created draft awaiting activation remains reusable on its original account. Prepared, submitted and unknown drafts cannot be discarded across accounts, and uncertain registrations are never blindly resubmitted. Archived records are not automatically restored or deleted; the storage layer provides validated, read-only recovery by record kind and ciphertext SHA256. Login and logout alone never trigger this replacement flow.

The official app's system firewall, TUN, split tunneling, DAITA, multihop and automatic key rotation are not plain account API controls. Multihop now has a separate adapter data-path implementation; see `tunnel-protection.md`. Other capabilities require their own supported engine/identity integration and cannot be represented as working account switches. The existing project controls its own city/transport/recovery and leaves the system ingress to Clash. Creating those features requires a separate supported data path, not copying the official UI.

Current tests use controlled official API responses and published RFC 7748 vectors. Compilation or mocks do not prove a real account login, voucher redemption, device revocation, production installation or an identity upgrade. Do not mutate the user's real account as a test.

## Windows account boundary

The ordinary-user Rust host exposes account commands over the user/session-bound named pipe. Tokens stay in RAM. Device listing also works before an identity is configured; every row is then marked as another device rather than fabricating a current-device match. Secret key-view replies are explicitly requested and excluded from public status, diagnostic reports and replay receipt caches. The Windows host selects API access using credential-free `GET /app/v1/api-addrs` requests before an account operation: recent successful cached address, the upstream-versioned official seed, remaining cached candidates, then the user's configured independent local Clash proxy and an already healthy adapter front if available. Address discovery and requests retain `https://api.mullvad.net/`, SNI, Host and normal certificate verification. A bounded 20-second preflight never sends account credentials; direct discovery has a 10-second sub-budget and each route at most 5 seconds. Direct candidates are capped at four per selection, including the official seed. Cache accepts at most 16 public port-443 addresses from a TLS-verified official response and stores the actual successful direct address separately, in current-user DPAPI. Invalid/empty/oversized lists cannot overwrite it. A selected client sends the account/device operation once; failures and uncertain mutations are not automatically replayed on another route. The strict single-proxy `MullvadClient::new` API remains available. API failures do not change the data tunnel.

A new generated Clash profile includes both the literal seed and the Windows agent process in the independent account/catalogue group, before business rules. Existing profiles need regeneration/activation for that protection. The group must not reference the adapter; a healthy front is considered separately only after actual connection readiness, so first login cannot wait for a missing tunnel. TLS validation stays enabled and redirects are disabled. API availability is separate from the current tunnel's availability.
# Mac 保存的本机身份

账号页支持列出本机保存的身份，默认只显示账号尾号，设备名来自保存的官方响应或明确刷新后的公钥匹配；没有匹配依据时显示待核实。可以主动切换身份并重连原节点。切换会短暂中断旧通道，不同时启动两份身份；新身份联网失败时仍可切回。官方设备列表不提供别的设备的私钥，只有本机已有密钥的身份才能切换。

私有 `identity-profiles.json` 保存账号、私钥、官方隧道地址和选择状态，不能放入 Git、诊断或安装包。旧模板保留，不能通过直接删除资料回滚运行中的新身份。首次迁移工具 `daemon/import-local-identities.rb` 从 `--state-dir` 的既有账号/模板及 `--device-json` 的本机私有官方设备记录读取两条身份；新增账号仅通过 stdin 提供。工具不会联系官方 API、启用身份或覆盖已有资料。此功能只覆盖 Mac；Windows 保持自己的安全存储合同。

## Mac complete management and recovery flow

The input login stays visible. Each saved profile offers `管理设备` (fresh login/list for that account only) and `启用身份` (exclusive data identity switch). Names and full device rows come from fresh official reads, not saved identity names. Entering the account page refreshes an existing login; subsequent local reads show monitor results without repeating official requests. Normal official monitoring is five minutes; failed API/data-path cases use a one-minute minimum recheck. Timestamps and stale/failure status remain visible.

A full account can list and remove an explicitly selected old device before creating a new one. Current-device removal remains protected unless the user has stopped all connections and explicitly confirms removal. After creation, use `POST /account/identity/save` with the exact receipt-backed account/device/key/addresses to preserve a new local choice, then the existing explicit identity switch endpoint. Official public keys alone cannot restore another machine's private key or assigned-address receipt. Unknown registrations remain reconcile-only.

`POST /disconnect` preempts normal operations, stops owned workers/front and automatic recovery, and persists stop intent across backend restarts. It keeps the local account API available; background remote account/metadata/health/maintenance checks pause while stopped. Explicitly opening management/refreshing can still use the independent account API. UI quit waits for the completed stop operation and a matching fresh stopped state. This is not an OS firewall or a change to other Clash routes. See the [behavior contract](../openspec/changes/account-device-recovery/specs/account/spec.md).

New Ruby modules must accompany the main daemon: account_api_routes.rb, account_lifecycle.rb and connection_control.rb. The payload stager/installer retain them and their per-file hashes; copying only the main script is not an upgrade. Actual installation, real device mutation and steady-state use are separate acceptance gates.

### Mac API request diagnostics and bounds

A TLS-validated API route choice is reused in memory for at most 15 minutes; this avoids another `api-addrs` request before every account transaction. Actual account/device data still refreshes normally. A changed physical network epoch or a transport failure invalidates that choice. The protected official-address cache remains available for the next discovery. Credentials and device mutations are never replayed automatically because a route failed; HTTP authentication errors remain distinct from transport errors.

Discovery allows up to 8 seconds per attempt, 4 seconds for connection establishment and 24 seconds in total. Its elapsed time is deducted from the complete 60-second account transaction before authenticated curl starts. Existing per-request 12-second bounds remain; normal five-minute monitoring and failure one-minute minimum intervals are unchanged. These are process waiting budgets, not guarantees against OS stalls or remote service failures.

`account-api-route-attempt`, `account-api-discovery-finished` and `account-api-request` events keep only allowlisted route/endpoint labels, validated peer/official IPs, proxy port, transaction ID, observed network epoch, curl exit/HTTP codes and timings. DNS, TCP, TLS, certificate, HTTP waiting and invalid-response failures have separate human messages. `dns_ms`, `tcp_ms`, `tls_ms` and `first_byte_ms` are cumulative curl milestones from request start, not independent stage durations; a proxy peer IP describes the proxy socket and cannot identify the remote origin's resolved IP. Raw stderr, reply bodies, URLs, device IDs, account numbers, tokens and keys are excluded. The account page shows the last request evidence for the selected management account, separately from registration evidence and its timestamp.

### Windows API request diagnostics and bounds

Windows uses the Rust account worker and ureq/Rustls, independently of the
WireGuard device key. A revoked tunnel device does not invalidate the account
number used to request a token and list devices. The login input stays available
while a management session exists; a failed replacement login retains the old
session and device snapshot. This does not add Mac's saved multi-identity UI to
Windows.

Each account job receives one 60-second monotonic deadline before discovery.
Credential-free, TLS-verified API-address discovery has a separate 24-second cap
and at most 8 seconds per attempt. The direct-address phase reserves one full
attempt for each configured fallback: independent loopback proxy, then an already
healthy adapter tunnel. With both available, direct discovery gets at most 8
seconds; with one or neither, at most 16 seconds. There is no dependency on an
unhealthy tunnel to authenticate. These are upper bounds, not mandatory waits.
The existing request/read bounds remain in force and the shared deadline clamps
all later authentication, reads and mutations. Failed account/device operations
are not automatically resent on another route; ambiguous writes still require
reconciliation.

The selected TLS-validated route can be reused for 15 minutes in memory. Network
binding observations, independent proxy configuration and healthy-tunnel instance
are part of its reuse key. A changed key, expiry, logout or transport failure
invalidates it. This route-proof counter only invalidates the API cache; it does
not initiate tunnel recovery. The protected official-address cache is separate.
Every new transaction binds fresh diagnostics and a fresh deadline; no token or
account number is stored in the route cache.

The account page and readable event list show route, last successful snapshot
time, HTTP status, elapsed time and conservative failure phase. Discovery reuse
is logged explicitly rather than pretending another discovery happened. ureq's
connection timeout covers TCP, proxy CONNECT and TLS together: Windows allows
up to 8 seconds for this combined setup, unlike Mac curl's 4-second TCP-only cap.
A setup timeout is labelled as uncertain between those stages. Header elapsed
time includes setup/request/header waiting; body time is measured separately.
No DNS/TCP/TLS substage duration is fabricated. A configured API address or local
proxy socket is not packet-capture proof of the physical route through an
external TUN.

Only closed endpoint/phase/error labels, bounded timings/statuses, transaction
IDs, route epochs and validated public API or loopback proxy sockets reach logs
and exports. No raw URL, response, account number, device identifier, token, key
or ureq error text is recorded. Logging uses the existing bounded nonblocking
queue. HTTP receipt is not tunnel health or proof that a device exists; API
failure preserves the last snapshot and is not labelled device revocation.
Tests use synthetic/loopback fixtures; native Windows execution, installation,
real account operations and real egress are separate acceptance gates.
