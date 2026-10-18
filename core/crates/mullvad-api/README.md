# Mullvad control-plane client

`adapter-mullvad-api` is a standalone synchronous REST client. It has no filesystem,
UI, tunnel lifecycle, registration, key import or persistence authority. Account
verification does not prove that a tunnel is connected.

The host supplies `BootstrapProxy::new(SocketAddr)` with literal `127.0.0.1` or
`::1`, port 1024–65535. The client always uses this HTTP CONNECT proxy. HTTPS is
restricted to the fixed `https://api.mullvad.net` root with normal rustls certificate
validation; there is no direct route, environment proxy override, target DNS
fallback, arbitrary URL or redirect following. Each complete public operation has
a 12-second deadline shared by all its requests, including token renewal and body
reading; connecting has an additional four-second bound. Relay bodies are capped
at 8 MiB and account bodies at 256 KiB. The host must validate relay bytes through
the catalogue parser before using or caching them.

Public entry points:

```rust,ignore
MullvadClient::new(proxy: BootstrapProxy) -> Result<MullvadClient, Error>
client.fetch_relays() -> Result<Vec<u8>, Error>
client.authenticate(number: AccountNumber) -> Result<AccountSession, Error>
client.read_account(session: &mut AccountSession, current_public_key: &str)
    -> Result<AccountSnapshot, Error>
client.remove_device(session: &AccountSession, id: &DeviceId) -> Result<(), Error>
client.redeem_voucher(session: &AccountSession, code: VoucherCode)
    -> Result<VoucherReceipt, Error>
```

The endpoint contracts follow the existing Ruby adapter: `POST auth/v1/token`
with `account_number`, `GET accounts/v1/accounts/me`, `GET accounts/v1/devices`,
`DELETE accounts/v1/devices/{id}`, and `POST app/v1/submit-voucher` with
`voucher_code`. Relay metadata is `GET app/v1/relays`. `AccountNumber::new(String)`
requires exactly 16 ASCII digits; `from_user_entry(String)` explicitly strips ASCII
spaces. Voucher input requires 8–32 ASCII alphanumeric characters. Device IDs are
canonical UUID strings; public keys have the canonical 32-byte base64 shape.

The host holds `AccountSession` privately. Account numbers, tokens and vouchers
use owned zeroizing buffers and have no Debug, Serialize, Clone or plaintext
accessor. The account/device/receipt DTOs are clonable and serializable, contain
no account number or token, and mark the current device only by exact equality
with the supplied public key. All client errors have stable `code()` values;
Debug/Display never include upstream bodies, credentials or underlying I/O text.
Zeroization covers this crate's owned secret buffers; HTTP/TLS library buffers,
allocator internals and the caller's original input remain outside that guarantee.

Only a definite HTTP 401 on a GET permits one token renewal across the whole
`read_account` operation. Mutation methods never retry or renew automatically.
Transport/body errors, 408, server errors, redirects or unexpected success
responses on a mutation produce `Error::OutcomeUnknown`. A malformed voucher
success also produces this result because redemption may have completed. The
host must remember its explicit operation ID, reconcile the official state, and
obtain a new deliberate submission before repeating an unknown mutation. The
host also owns authorization, protection of the current device, idempotence and
local login storage; passing a typed ID is not user confirmation.

Run `cargo +1.97.1 test -p adapter-mullvad-api` from the core workspace. Tests use
synthetic responses and one local CONNECT proxy; they never use a real account,
send a voucher, remove a device or contact the official API. Compile-fail docs
guard credential/session Debug and Serialize exclusions. Real account and
Windows route acceptance remain separate gates.
