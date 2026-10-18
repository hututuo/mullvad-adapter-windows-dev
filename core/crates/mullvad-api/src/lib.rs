//! Bounded Mullvad control-plane operations over explicit HTTPS routing.
//! This module has no tunnel, identity creation, persistence or UI authority.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const ROOT: &str = "https://api.mullvad.net/";
const DEADLINE: Duration = Duration::from_secs(12);
// Account snapshots require two sequential GETs through the user's bootstrap
// proxy. Share a bounded budget across those GETs (and any one token renewal),
// allowing ordinary high-latency exits without extending mutation timeouts.
const ACCOUNT_READ_DEADLINE: Duration = Duration::from_secs(30);
const ACCOUNT_BODY_CAP: usize = 256 * 1024;
pub const RELAY_BODY_CAP: usize = 8 * 1024 * 1024;

/// Contains no credentials; only the two literal localhost addresses are allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootstrapProxy(SocketAddr);

impl BootstrapProxy {
    pub fn new(address: SocketAddr) -> Result<Self, Error> {
        if address.port() < 1024
            || !matches!(address.ip(), IpAddr::V4(ip) if ip == Ipv4Addr::LOCALHOST)
                && !matches!(address.ip(), IpAddr::V6(ip) if ip == Ipv6Addr::LOCALHOST)
        {
            return Err(Error::InvalidProxy);
        }
        Ok(Self(address))
    }
}

/// An account secret with no formatting, serialization or plaintext accessor.
/// ```compile_fail
/// let number = adapter_mullvad_api::AccountNumber::new("0000000000000000".into()).unwrap();
/// println!("{number:?}");
/// ```
/// ```compile_fail
/// let number = adapter_mullvad_api::AccountNumber::new("0000000000000000".into()).unwrap();
/// let _ = serde_json::to_string(&number);
/// ```
pub struct AccountNumber(Zeroizing<String>);

impl AccountNumber {
    /// Takes ownership so the caller need not leave a second owned copy behind.
    pub fn new(value: String) -> Result<Self, Error> {
        let value = Zeroizing::new(value);
        if value.len() != 16 || !value.bytes().all(|c| c.is_ascii_digit()) {
            return Err(Error::InvalidAccountNumber);
        }
        Ok(Self(value))
    }

    /// Explicit entry normalization removes ASCII spaces only (not punctuation).
    pub fn from_user_entry(value: String) -> Result<Self, Error> {
        let mut value = Zeroizing::new(value);
        value.retain(|c| c != ' ');
        Self::new(std::mem::take(&mut *value))
    }
}

/// An explicit mutation input, also excluded from Debug and serialization.
pub struct VoucherCode(Zeroizing<String>);

impl VoucherCode {
    pub fn new(value: String) -> Result<Self, Error> {
        let value = Zeroizing::new(value);
        if !(8..=32).contains(&value.len()) || !value.bytes().all(|c| c.is_ascii_alphanumeric()) {
            return Err(Error::InvalidVoucherCode);
        }
        Ok(Self(value))
    }
}

/// Restricted canonical UUID; cannot inject a path, query or fragment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct DeviceId(String);

impl DeviceId {
    pub fn new(value: String) -> Result<Self, Error> {
        if value.len() != 36
            || !value.bytes().enumerate().all(|(i, c)| {
                if [8, 13, 18, 23].contains(&i) {
                    c == b'-'
                } else {
                    c.is_ascii_hexdigit()
                }
            })
        {
            return Err(Error::InvalidDeviceId);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

struct AccessToken(Zeroizing<String>);

/// Keep privately in the host. Dropping this clears its owned account/token buffers.
/// No Clone, Debug, Serialize or credential accessor is provided.
/// ```compile_fail
/// fn log_session(session: &adapter_mullvad_api::AccountSession) {
///     println!("{session:?}");
/// }
/// ```
/// ```compile_fail
/// fn export_session(session: &adapter_mullvad_api::AccountSession) {
///     let _ = serde_json::to_string(session);
/// }
/// ```
/// ```compile_fail
/// fn expose_account(session: &adapter_mullvad_api::AccountSession) -> &str {
///     session.account_number()
/// }
/// ```
pub struct AccountSession {
    number: AccountNumber,
    token: AccessToken,
}

impl AccountSession {
    /// Returns the lowercase SHA-256 fingerprint of the full account number for
    /// binding local pending-operation records across sessions. The account number
    /// and access token remain private and are never included in the returned value.
    pub fn binding_fingerprint(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let digest = Sha256::digest(self.number.0.as_bytes());
        let mut fingerprint = String::with_capacity(64);
        for byte in digest {
            fingerprint.push(char::from(HEX[(byte >> 4) as usize]));
            fingerprint.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
        fingerprint
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Device {
    pub id: DeviceId,
    pub name: String,
    pub pubkey: String,
    pub created: String,
    pub current: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AccountSnapshot {
    pub expiry: String,
    pub devices: Vec<Device>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VoucherReceipt {
    pub time_added: u64,
    pub new_expiry: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AssignedAddresses {
    pub ipv4_address: String,
    pub ipv6_address: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CreatedDevice {
    pub device: Device,
    pub addresses: AssignedAddresses,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    InvalidAccount,
    InvalidAccessToken,
    InvalidVoucher,
    VoucherUsed,
    DeviceNotFound,
    PublicKeyInUse,
    Other,
}

/// Safe to format/log. Never contains an upstream body, URL or input credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidProxy,
    InvalidAccountNumber,
    InvalidVoucherCode,
    InvalidDeviceId,
    InvalidPublicKey,
    Unreachable,
    ProxyConnectFailed,
    TlsFailed,
    DeadlineExceeded,
    ResponseTooLarge,
    InvalidResponse,
    Rejected {
        status: u16,
        reason: Rejection,
    },
    /// A mutation may have completed: the caller must reconcile before resubmission.
    OutcomeUnknown,
}

impl Error {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidProxy => "invalid_bootstrap_proxy",
            Self::InvalidAccountNumber => "invalid_account_number",
            Self::InvalidVoucherCode => "invalid_voucher_code",
            Self::InvalidDeviceId => "invalid_device_id",
            Self::InvalidPublicKey => "invalid_public_key",
            Self::Unreachable => "api_unreachable",
            Self::ProxyConnectFailed => "api_proxy_tunnel_failed",
            Self::TlsFailed => "api_tls_failed",
            Self::DeadlineExceeded => "api_deadline_exceeded",
            Self::ResponseTooLarge => "api_response_too_large",
            Self::InvalidResponse => "invalid_api_response",
            Self::OutcomeUnknown => "mutation_outcome_unknown",
            Self::Rejected { reason, .. } => match reason {
                Rejection::InvalidAccount => "invalid_account",
                Rejection::InvalidAccessToken => "invalid_access_token",
                Rejection::InvalidVoucher => "invalid_voucher",
                Rejection::VoucherUsed => "voucher_used",
                Rejection::DeviceNotFound => "device_not_found",
                Rejection::PublicKeyInUse => "public_key_in_use",
                Rejection::Other => "api_rejected",
            },
        }
    }
    pub fn requires_reconciliation(self) -> bool {
        self == Self::OutcomeUnknown
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for Error {}

pub struct MullvadClient {
    transport: HttpTransport,
}

impl MullvadClient {
    pub fn new(proxy: BootstrapProxy) -> Result<Self, Error> {
        Ok(Self {
            transport: HttpTransport::new(proxy)?,
        })
    }

    /// HTTPS over system routing, explicitly ignoring environment proxy settings.
    /// This does not promise physical-interface bypass: an external TUN must
    /// route api.mullvad.net independently of this adapter to avoid a bootstrap loop.
    /// No automatic transport fallback or mutation replay is performed.
    pub fn direct() -> Result<Self, Error> {
        Ok(Self {
            transport: HttpTransport::with_proxy(None)?,
        })
    }

    /// Only fetches bounded bytes. The host must validate with the catalogue parser.
    pub fn fetch_relays(&self) -> Result<Vec<u8>, Error> {
        let response = self.transport.request(
            Method::Get,
            "app/v1/relays",
            None,
            None,
            Instant::now() + DEADLINE,
            RELAY_BODY_CAP,
        )?;
        require_success(&response, false, &[200])?;
        Ok(response.body.to_vec())
    }

    pub fn authenticate(&self, number: AccountNumber) -> Result<AccountSession, Error> {
        authenticate(
            &self.transport,
            number,
            Instant::now() + ACCOUNT_READ_DEADLINE,
        )
    }

    /// Gets account and devices atomically as an output (no partial snapshot).
    /// Across both GETs, at most one definite 401 renews the token.
    pub fn read_account(
        &self,
        session: &mut AccountSession,
        current_public_key: &str,
    ) -> Result<AccountSnapshot, Error> {
        read_account(
            &self.transport,
            session,
            current_public_key,
            Instant::now() + ACCOUNT_READ_DEADLINE,
        )
    }

    /// Reads account details and the registered device list before a local tunnel identity
    /// exists. The returned devices are all marked `current: false`.
    /// Across both GETs, at most one definite 401 renews the token.
    pub fn read_account_devices(
        &self,
        session: &mut AccountSession,
    ) -> Result<AccountSnapshot, Error> {
        read_account_inner(
            &self.transport,
            session,
            None,
            Instant::now() + ACCOUNT_READ_DEADLINE,
        )
    }

    /// Explicit mutation; no automatic retry, including on 401.
    pub fn remove_device(&self, session: &AccountSession, id: &DeviceId) -> Result<(), Error> {
        remove_device(&self.transport, session, id, Instant::now() + DEADLINE)
    }

    /// Explicit mutation; consumes the voucher and never automatically redelivers it.
    pub fn redeem_voucher(
        &self,
        session: &AccountSession,
        code: VoucherCode,
    ) -> Result<VoucherReceipt, Error> {
        redeem_voucher(&self.transport, session, code, Instant::now() + DEADLINE)
    }

    /// Registers a locally generated public key and returns both assigned tunnel addresses.
    /// This method accepts only the public key; private-key generation and storage belong to
    /// the platform host. The caller must reconcile `OutcomeUnknown` before another POST.
    pub fn create_device(
        &self,
        session: &AccountSession,
        public_key: &str,
    ) -> Result<CreatedDevice, Error> {
        create_device(
            &self.transport,
            session,
            public_key,
            Instant::now() + DEADLINE,
        )
    }

    /// Replaces a registered device's public key and returns its newly assigned addresses.
    /// The caller owns the corresponding private key and must reconcile `OutcomeUnknown` before
    /// another PUT.
    pub fn replace_device_key(
        &self,
        session: &AccountSession,
        id: &DeviceId,
        public_key: &str,
    ) -> Result<AssignedAddresses, Error> {
        replace_device_key(
            &self.transport,
            session,
            id,
            public_key,
            Instant::now() + DEADLINE,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Method {
    Get,
    Post,
    Put,
    Delete,
}
struct Response {
    status: u16,
    body: Zeroizing<Vec<u8>>,
}
trait Transport {
    fn request(
        &self,
        method: Method,
        path: &str,
        token: Option<&AccessToken>,
        body: Option<&str>,
        deadline: Instant,
        cap: usize,
    ) -> Result<Response, Error>;
}
struct HttpTransport {
    agent: ureq::Agent,
}

impl HttpTransport {
    fn new(proxy: BootstrapProxy) -> Result<Self, Error> {
        Self::with_proxy(Some(proxy))
    }
    fn with_proxy(proxy: Option<BootstrapProxy>) -> Result<Self, Error> {
        let proxy = proxy
            .map(|proxy| {
                ureq::Proxy::new(&format!("http://{}", proxy.0)).map_err(|_| Error::InvalidProxy)
            })
            .transpose()?;
        // Explicit proxy overwrites environment discovery. Proxy::new has no NO_PROXY
        // exclusions and HTTP CONNECT resolves api.mullvad.net at the proxy.
        let config = ureq::Agent::config_builder()
            .proxy(proxy)
            .https_only(true)
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(DEADLINE))
            // ureq's connect phase includes the remote CONNECT negotiation and
            // TLS handshake, not just the local proxy socket. Each request's
            // remaining global deadline still clamps this upper bound, including
            // the shorter mutation deadline.
            .timeout_connect(Some(ACCOUNT_READ_DEADLINE))
            .build();
        Ok(Self {
            agent: config.new_agent(),
        })
    }
}

impl Transport for HttpTransport {
    fn request(
        &self,
        method: Method,
        path: &str,
        token: Option<&AccessToken>,
        body: Option<&str>,
        deadline: Instant,
        cap: usize,
    ) -> Result<Response, Error> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or(Error::DeadlineExceeded)?;
        let url = format!("{ROOT}{path}");
        let authorization = token.map(|t| Zeroizing::new(format!("Bearer {}", &*t.0)));
        let result = match method {
            Method::Get | Method::Delete => {
                let mut request = if method == Method::Get {
                    self.agent.get(&url)
                } else {
                    self.agent.delete(&url)
                };
                if let Some(value) = &authorization {
                    request = request.header("Authorization", &**value);
                }
                request
                    .config()
                    .timeout_global(Some(remaining))
                    .build()
                    .call()
            }
            Method::Post | Method::Put => {
                let request = match method {
                    Method::Post => self.agent.post(&url),
                    Method::Put => self.agent.put(&url),
                    Method::Get | Method::Delete => unreachable!(),
                };
                let mut request = request.header("Content-Type", "application/json");
                if let Some(value) = &authorization {
                    request = request.header("Authorization", &**value);
                }
                request
                    .config()
                    .timeout_global(Some(remaining))
                    .build()
                    .send(body.unwrap_or("").as_bytes())
            }
        };
        // Never propagate ureq diagnostic text, headers, bodies, or URLs.
        let mut response = result.map_err(classify_transport_error)?;
        let status = response.status().as_u16();
        let body = read_bounded(response.body_mut().as_reader(), cap)?;
        if Instant::now() > deadline {
            return Err(Error::DeadlineExceeded);
        }
        Ok(Response { status, body })
    }
}

fn classify_transport_error(error: ureq::Error) -> Error {
    // Discard all diagnostic strings, headers and certificate details. A CONNECT
    // error can mean a proxy rejection or EOF; it is not an API account rejection.
    match error {
        ureq::Error::Timeout(_) => Error::DeadlineExceeded,
        ureq::Error::Io(error) if error.kind() == std::io::ErrorKind::TimedOut => {
            Error::DeadlineExceeded
        }
        ureq::Error::ConnectProxyFailed(_) => Error::ProxyConnectFailed,
        ureq::Error::Rustls(_) | ureq::Error::Tls(_) => Error::TlsFailed,
        _ => Error::Unreachable,
    }
}

fn read_bounded(reader: impl Read, cap: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    // Reserve the maximum once: reallocations could leave previous secret bytes
    // in an allocator's freed block before the final buffer is zeroized.
    let mut bytes = Zeroizing::new(Vec::with_capacity(cap + 1));
    reader
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Unreachable)?;
    if bytes.len() > cap {
        return Err(Error::ResponseTooLarge);
    }
    Ok(bytes)
}

#[derive(Serialize)]
struct AuthPayload<'a> {
    account_number: &'a str,
}
#[derive(Serialize)]
struct VoucherPayload<'a> {
    voucher_code: &'a str,
}
#[derive(Serialize)]
struct DevicePayload<'a> {
    pubkey: &'a str,
    hijack_dns: bool,
}
#[derive(Serialize)]
struct DeviceKeyPayload<'a> {
    pubkey: &'a str,
}

fn auth_token(
    transport: &impl Transport,
    number: &AccountNumber,
    deadline: Instant,
) -> Result<AccessToken, Error> {
    let body = Zeroizing::new(
        serde_json::to_string(&AuthPayload {
            account_number: &number.0,
        })
        .map_err(|_| Error::InvalidResponse)?,
    );
    let response = transport.request(
        Method::Post,
        "auth/v1/token",
        None,
        Some(&body),
        deadline,
        ACCOUNT_BODY_CAP,
    )?;
    require_success(&response, false, &[200, 201])?;
    // Token strings are moved straight into zeroizing storage, without Value copies.
    #[derive(Deserialize)]
    struct AuthResponse {
        #[serde(deserialize_with = "decode_secret")]
        access_token: Zeroizing<String>,
        expiry: String,
    }
    let auth: AuthResponse = decode(&response.body)?;
    if !valid_timestamp(&auth.expiry)
        || auth.access_token.is_empty()
        || auth.access_token.len() > 8192
        || !auth
            .access_token
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b))
    {
        return Err(Error::InvalidResponse);
    }
    Ok(AccessToken(auth.access_token))
}

fn decode_secret<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}

fn authenticate(
    transport: &impl Transport,
    number: AccountNumber,
    deadline: Instant,
) -> Result<AccountSession, Error> {
    let token = auth_token(transport, &number, deadline)?;
    Ok(AccountSession { number, token })
}

fn get_authenticated(
    transport: &impl Transport,
    session: &mut AccountSession,
    path: &str,
    renewed: &mut bool,
    deadline: Instant,
) -> Result<Response, Error> {
    let mut response = transport.request(
        Method::Get,
        path,
        Some(&session.token),
        None,
        deadline,
        ACCOUNT_BODY_CAP,
    )?;
    if response.status == 401 && !*renewed {
        *renewed = true;
        session.token = auth_token(transport, &session.number, deadline)?;
        response = transport.request(
            Method::Get,
            path,
            Some(&session.token),
            None,
            deadline,
            ACCOUNT_BODY_CAP,
        )?;
    }
    require_success(&response, false, &[200])?;
    Ok(response)
}

fn read_account(
    transport: &impl Transport,
    session: &mut AccountSession,
    public_key: &str,
    deadline: Instant,
) -> Result<AccountSnapshot, Error> {
    if !valid_public_key(public_key) {
        return Err(Error::InvalidPublicKey);
    }
    read_account_inner(transport, session, Some(public_key), deadline)
}

fn read_account_inner(
    transport: &impl Transport,
    session: &mut AccountSession,
    current_public_key: Option<&str>,
    deadline: Instant,
) -> Result<AccountSnapshot, Error> {
    if current_public_key.is_some_and(|key| !valid_public_key(key)) {
        return Err(Error::InvalidPublicKey);
    }
    let mut renewed = false;
    let account = get_authenticated(
        transport,
        session,
        "accounts/v1/accounts/me",
        &mut renewed,
        deadline,
    )?;
    #[derive(Deserialize)]
    struct AccountResponse {
        expiry: String,
    }
    let account: AccountResponse = decode(&account.body)?;
    if !valid_timestamp(&account.expiry) {
        return Err(Error::InvalidResponse);
    }
    let devices = get_authenticated(
        transport,
        session,
        "accounts/v1/devices",
        &mut renewed,
        deadline,
    )?;
    let devices = decode_devices_for_account(&devices.body, current_public_key)?;
    Ok(AccountSnapshot {
        expiry: account.expiry,
        devices,
    })
}

#[cfg(test)]
fn decode_devices(bytes: &[u8], public_key: &str) -> Result<Vec<Device>, Error> {
    decode_devices_for_account(bytes, Some(public_key))
}

fn decode_devices_for_account(
    bytes: &[u8],
    current_public_key: Option<&str>,
) -> Result<Vec<Device>, Error> {
    #[derive(Deserialize)]
    struct RawDevice {
        id: String,
        name: String,
        pubkey: String,
        created: String,
    }
    let raw: Vec<RawDevice> = decode(bytes)?;
    if raw.len() > 64 {
        return Err(Error::InvalidResponse);
    }
    let mut result = Vec::with_capacity(raw.len());
    for device in raw {
        let id = DeviceId::new(device.id).map_err(|_| Error::InvalidResponse)?;
        if device.name.is_empty()
            || device.name.len() > 256
            || device.name.chars().any(char::is_control)
            || !valid_public_key(&device.pubkey)
            || !valid_timestamp(&device.created)
            || result.iter().any(|d: &Device| d.id == id)
        {
            return Err(Error::InvalidResponse);
        }
        result.push(Device {
            id,
            name: device.name,
            current: current_public_key.is_some_and(|key| device.pubkey == key),
            pubkey: device.pubkey,
            created: device.created,
        });
    }
    Ok(result)
}

fn remove_device(
    transport: &impl Transport,
    session: &AccountSession,
    id: &DeviceId,
    deadline: Instant,
) -> Result<(), Error> {
    let response = transport
        .request(
            Method::Delete,
            &format!("accounts/v1/devices/{}", id.as_str()),
            Some(&session.token),
            None,
            deadline,
            ACCOUNT_BODY_CAP,
        )
        .map_err(|_| Error::OutcomeUnknown)?;
    require_success(&response, true, &[204])
}

fn redeem_voucher(
    transport: &impl Transport,
    session: &AccountSession,
    code: VoucherCode,
    deadline: Instant,
) -> Result<VoucherReceipt, Error> {
    let body = Zeroizing::new(
        serde_json::to_string(&VoucherPayload {
            voucher_code: &code.0,
        })
        .map_err(|_| Error::InvalidResponse)?,
    );
    let response = transport
        .request(
            Method::Post,
            "app/v1/submit-voucher",
            Some(&session.token),
            Some(&body),
            deadline,
            ACCOUNT_BODY_CAP,
        )
        .map_err(|_| Error::OutcomeUnknown)?;
    require_success(&response, true, &[200])?;
    #[derive(Deserialize)]
    struct Receipt {
        time_added: u64,
        new_expiry: String,
    }
    let receipt: Receipt = decode(&response.body).map_err(|_| Error::OutcomeUnknown)?;
    if receipt.time_added == 0 || !valid_timestamp(&receipt.new_expiry) {
        return Err(Error::OutcomeUnknown);
    }
    Ok(VoucherReceipt {
        time_added: receipt.time_added,
        new_expiry: receipt.new_expiry,
    })
}

fn create_device(
    transport: &impl Transport,
    session: &AccountSession,
    public_key: &str,
    deadline: Instant,
) -> Result<CreatedDevice, Error> {
    if !valid_public_key(public_key) {
        return Err(Error::InvalidPublicKey);
    }
    let body = Zeroizing::new(
        serde_json::to_string(&DevicePayload {
            pubkey: public_key,
            hijack_dns: false,
        })
        .map_err(|_| Error::InvalidResponse)?,
    );
    let response = transport
        .request(
            Method::Post,
            "accounts/v1/devices",
            Some(&session.token),
            Some(&body),
            deadline,
            ACCOUNT_BODY_CAP,
        )
        .map_err(|_| Error::OutcomeUnknown)?;
    require_success(&response, true, &[201])?;
    let created: RawCreatedDevice = decode(&response.body).map_err(|_| Error::OutcomeUnknown)?;
    let id = DeviceId::new(created.id).map_err(|_| Error::OutcomeUnknown)?;
    let addresses = assigned_addresses(created.ipv4_address, created.ipv6_address)
        .map_err(|_| Error::OutcomeUnknown)?;
    if created.name.is_empty()
        || created.name.len() > 256
        || created.name.chars().any(char::is_control)
        || created.pubkey != public_key
        || !valid_timestamp(&created.created)
        || created.hijack_dns
    {
        return Err(Error::OutcomeUnknown);
    }
    Ok(CreatedDevice {
        device: Device {
            id,
            name: created.name,
            pubkey: created.pubkey,
            created: created.created,
            current: true,
        },
        addresses,
    })
}

fn replace_device_key(
    transport: &impl Transport,
    session: &AccountSession,
    id: &DeviceId,
    public_key: &str,
    deadline: Instant,
) -> Result<AssignedAddresses, Error> {
    if !valid_public_key(public_key) {
        return Err(Error::InvalidPublicKey);
    }
    let body = Zeroizing::new(
        serde_json::to_string(&DeviceKeyPayload { pubkey: public_key })
            .map_err(|_| Error::InvalidResponse)?,
    );
    let response = transport
        .request(
            Method::Put,
            &format!("accounts/v1/devices/{}/pubkey", id.as_str()),
            Some(&session.token),
            Some(&body),
            deadline,
            ACCOUNT_BODY_CAP,
        )
        .map_err(|_| Error::OutcomeUnknown)?;
    require_success(&response, true, &[200])?;
    let replaced: RawReplacedDeviceKey =
        decode(&response.body).map_err(|_| Error::OutcomeUnknown)?;
    let response_id = DeviceId::new(replaced.id).map_err(|_| Error::OutcomeUnknown)?;
    let addresses = assigned_addresses(replaced.ipv4_address, replaced.ipv6_address)
        .map_err(|_| Error::OutcomeUnknown)?;
    if response_id != *id || replaced.pubkey != public_key {
        return Err(Error::OutcomeUnknown);
    }
    Ok(addresses)
}

#[derive(Deserialize)]
struct RawCreatedDevice {
    id: String,
    name: String,
    pubkey: String,
    created: String,
    ipv4_address: String,
    ipv6_address: String,
    hijack_dns: bool,
}

#[derive(Deserialize)]
struct RawReplacedDeviceKey {
    id: String,
    pubkey: String,
    ipv4_address: String,
    ipv6_address: String,
}

fn assigned_addresses(
    ipv4_address: String,
    ipv6_address: String,
) -> Result<AssignedAddresses, Error> {
    if !valid_assigned_ipv4(&ipv4_address) || !valid_assigned_ipv6(&ipv6_address) {
        return Err(Error::InvalidResponse);
    }
    Ok(AssignedAddresses {
        ipv4_address,
        ipv6_address,
    })
}

fn valid_assigned_ipv4(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    prefix == "32"
        && address.parse::<Ipv4Addr>().is_ok_and(|address| {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_link_local()
                && !address.is_multicast()
        })
}

fn valid_assigned_ipv6(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    prefix == "128"
        && address.parse::<Ipv6Addr>().is_ok_and(|address| {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_unicast_link_local()
                && !address.is_multicast()
                && address.to_ipv4_mapped().is_none()
        })
}

fn require_success(response: &Response, mutation: bool, accepted: &[u16]) -> Result<(), Error> {
    if accepted.contains(&response.status) {
        return Ok(());
    }
    if mutation && (!(400..500).contains(&response.status) || response.status == 408) {
        return Err(Error::OutcomeUnknown);
    }
    #[derive(Deserialize)]
    struct ApiError {
        code: Option<String>,
        #[serde(rename = "type")]
        kind: Option<String>,
    }
    let reason = serde_json::from_slice::<ApiError>(&response.body)
        .ok()
        .and_then(|e| e.code.or(e.kind));
    let reason = match reason.as_deref() {
        Some("INVALID_ACCOUNT") => Rejection::InvalidAccount,
        Some("INVALID_ACCESS_TOKEN") => Rejection::InvalidAccessToken,
        Some("INVALID_VOUCHER") => Rejection::InvalidVoucher,
        Some("VOUCHER_USED") => Rejection::VoucherUsed,
        Some("DEVICE_NOT_FOUND") => Rejection::DeviceNotFound,
        Some("PUBKEY_IN_USE") => Rejection::PublicKeyInUse,
        _ if response.status == 401 => Rejection::InvalidAccessToken,
        _ => Rejection::Other,
    };
    Err(Error::Rejected {
        status: response.status,
        reason,
    })
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    serde_json::from_slice(bytes).map_err(|_| Error::InvalidResponse)
}

fn valid_public_key(key: &str) -> bool {
    let b = key.as_bytes();
    b.len() == 44 && b[43] == b'=' && b[..43].iter().all(|c| c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/')
        // 32-byte canonical base64 has two unused low bits in its final sextet.
        && b"AEIMQUYcgkosw048".contains(&b[42])
}

// Validate the returned RFC3339 shape and calendar without introducing a clock library.
fn valid_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 20
        || [4, 7].iter().any(|i| b[*i] != b'-')
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return false;
    }
    let number = |range: std::ops::Range<usize>| -> Option<u32> {
        let v = b.get(range)?;
        if !v.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(v).ok()?.parse().ok()
    };
    let (Some(y), Some(m), Some(d), Some(h), Some(min), Some(sec)) = (
        number(0..4),
        number(5..7),
        number(8..10),
        number(11..13),
        number(14..16),
        number(17..19),
    ) else {
        return false;
    };
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if y == 0 || d == 0 || d > days || h > 23 || min > 59 || sec > 59 {
        return false;
    }
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start || i - start > 9 {
            return false;
        }
    }
    if b.get(i) == Some(&b'Z') {
        return i + 1 == b.len();
    }
    if !matches!(b.get(i), Some(b'+') | Some(b'-')) || b.len() != i + 6 || b[i + 3] != b':' {
        return false;
    }
    matches!((number(i+1..i+3), number(i+4..i+6)), (Some(h), Some(m)) if h <= 23 && m <= 59)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::net::TcpListener;

    #[test]
    fn transport_diagnostics_keep_only_closed_categories() {
        for timeout in [
            ureq::Timeout::Connect,
            ureq::Timeout::Global,
            ureq::Timeout::RecvBody,
        ] {
            assert_eq!(
                classify_transport_error(ureq::Error::Timeout(timeout)),
                Error::DeadlineExceeded
            );
        }
        assert_eq!(
            classify_transport_error(ureq::Error::Io(std::io::Error::from(
                std::io::ErrorKind::TimedOut
            ))),
            Error::DeadlineExceeded
        );
        let upstream_detail = "synthetic-sensitive-upstream-header";
        let proxy =
            classify_transport_error(ureq::Error::ConnectProxyFailed(upstream_detail.into()));
        let tls = classify_transport_error(ureq::Error::Tls(upstream_detail));
        assert_eq!(proxy, Error::ProxyConnectFailed);
        assert_eq!(tls, Error::TlsFailed);
        for error in [proxy, tls] {
            assert!(!format!("{error} {error:?}").contains(upstream_detail));
            assert!(error.code().starts_with("api_"));
        }
        assert_eq!(
            classify_transport_error(ureq::Error::Io(std::io::Error::from(
                std::io::ErrorKind::ConnectionRefused
            ))),
            Error::Unreachable
        );
    }

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const OTHER_KEY: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=";
    const ID: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const AUTH: &str = r#"{"access_token":"synthetic-token","expiry":"2030-01-01T00:00:00Z"}"#;
    const ACCOUNT: &str = r#"{"expiry":"2030-01-01T00:00:00Z"}"#;

    fn response(status: u16, body: &str) -> Result<Response, Error> {
        Ok(Response {
            status,
            body: Zeroizing::new(body.as_bytes().to_vec()),
        })
    }
    fn number() -> AccountNumber {
        AccountNumber::new("0000000000000000".into()).unwrap()
    }
    fn session() -> AccountSession {
        session_with_account("0000000000000000")
    }
    fn session_with_account(value: &str) -> AccountSession {
        session_with_account_and_token(value, "synthetic-token")
    }
    fn session_with_account_and_token(value: &str, token: &str) -> AccountSession {
        AccountSession {
            number: AccountNumber::new(value.to_owned()).unwrap(),
            token: AccessToken(Zeroizing::new(token.to_owned())),
        }
    }
    struct Script {
        replies: RefCell<VecDeque<Result<Response, Error>>>,
        calls: RefCell<Vec<Call>>,
    }
    struct Call {
        method: Method,
        path: String,
        body: Option<String>,
        has_token: bool,
        deadline: Instant,
    }
    impl Script {
        fn new(replies: Vec<Result<Response, Error>>) -> Self {
            Self {
                replies: RefCell::new(replies.into()),
                calls: RefCell::new(Vec::new()),
            }
        }
    }
    impl Transport for Script {
        fn request(
            &self,
            method: Method,
            path: &str,
            _token: Option<&AccessToken>,
            body: Option<&str>,
            deadline: Instant,
            cap: usize,
        ) -> Result<Response, Error> {
            assert_eq!(cap, ACCOUNT_BODY_CAP);
            self.calls.borrow_mut().push(Call {
                method,
                path: path.into(),
                body: body.map(str::to_owned),
                has_token: _token.is_some(),
                deadline,
            });
            self.replies
                .borrow_mut()
                .pop_front()
                .expect("unexpected request")
        }
    }

    #[test]
    fn credentials_reject_non_ascii_and_only_normalize_explicit_spaces() {
        assert!(AccountNumber::new("0000 0000 0000 0000".into()).is_err());
        assert!(AccountNumber::from_user_entry("0000 0000 0000 0000".into()).is_ok());
        for value in [
            "000000000000000",
            "00000000000000000",
            "００００００００００００００００",
            "0000-0000-0000-0000",
            "000000000000000\n",
        ] {
            assert!(AccountNumber::from_user_entry(value.into()).is_err());
        }
        for value in ["short", "test-code-123", "abcd1234\r\n", "兑换兑换兑换兑换"] {
            assert!(VoucherCode::new(value.into()).is_err());
        }
        assert!(VoucherCode::new("Abcd1234".into()).is_ok());
    }

    #[test]
    fn account_session_fingerprint_is_stable_and_uses_the_full_account_number() {
        let first_session = session_with_account("0000000000000000");
        let renewed_session =
            session_with_account_and_token("0000000000000000", "renewed-synthetic-token");
        let same_tail_different_account = session_with_account("9999999999990000");

        let fingerprint = first_session.binding_fingerprint();
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        assert_eq!(
            fingerprint,
            "fcdb4b423f4e5283afa249d762ef6aef150e91fccd810d43e5e719d14512dec7"
        );
        assert_eq!(fingerprint, renewed_session.binding_fingerprint());
        assert_ne!(
            fingerprint,
            same_tail_different_account.binding_fingerprint()
        );
        assert!(!fingerprint.contains("0000000000000000"));
    }

    #[test]
    fn proxy_only_accepts_literal_loopback_and_unprivileged_ports() {
        for value in ["127.0.0.1:1024", "127.0.0.1:65535", "[::1]:7897"] {
            assert!(BootstrapProxy::new(value.parse().unwrap()).is_ok());
        }
        for value in [
            "127.0.0.1:1023",
            "127.0.0.1:0",
            "127.0.0.2:7897",
            "192.0.2.1:7897",
            "[::ffff:127.0.0.1]:7897",
        ] {
            assert_eq!(
                BootstrapProxy::new(value.parse().unwrap()).unwrap_err(),
                Error::InvalidProxy
            );
        }
        let http =
            HttpTransport::new(BootstrapProxy::new("127.0.0.1:7897".parse().unwrap()).unwrap())
                .unwrap();
        let config = http.agent.config();
        assert!(config.https_only());
        assert!(!config.tls_config().disable_verification());
        assert_eq!(
            config.tls_config().provider(),
            ureq::tls::TlsProvider::Rustls
        );
        assert_eq!(config.max_redirects(), 0);
        assert!(!config.http_status_as_error());
        assert_eq!(config.timeouts().global, Some(DEADLINE));
        assert!(config.proxy().is_some());
    }

    #[test]
    fn device_id_blocks_url_injection() {
        assert_eq!(DeviceId::new(ID.to_uppercase()).unwrap().as_str(), ID);
        for value in [
            "../me",
            "?account_number=1234",
            "01234567-89ab-cdef-0123-456789abcdef/",
            "01234567-89ab-cdef-0123-456789abcdeg",
        ] {
            assert!(DeviceId::new(value.into()).is_err());
        }
    }

    #[test]
    fn direct_api_never_discovers_an_environment_proxy_or_relaxes_tls() {
        let http = HttpTransport::with_proxy(None).unwrap();
        let c = http.agent.config();
        assert!(c.proxy().is_none());
        assert!(c.https_only());
        assert!(!c.tls_config().disable_verification());
        assert_eq!(c.max_redirects(), 0);
        assert_eq!(c.timeouts().global, Some(DEADLINE));
    }

    #[test]
    fn response_caps_and_io_failures_are_safe() {
        assert_eq!(&*read_bounded(&b"1234"[..], 4).unwrap(), b"1234");
        assert_eq!(
            read_bounded(&b"12345"[..], 4).unwrap_err(),
            Error::ResponseTooLarge
        );
        struct Fail;
        impl Read for Fail {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("secret input must not escape"))
            }
        }
        assert_eq!(
            read_bounded(Fail, 4).unwrap_err().to_string(),
            "api_unreachable"
        );
    }

    #[test]
    fn authentication_decodes_secret_without_echoing_bad_body() {
        let transport = Script::new(vec![response(200, AUTH)]);
        assert!(authenticate(&transport, number(), Instant::now() + DEADLINE).is_ok());
        for body in [
            r#"{"access_token":"secret\r\nHeader: x","expiry":"2030-01-01T00:00:00Z"}"#,
            r#"{"access_token":"secret","expiry":"bad"}"#,
            "secret invalid JSON",
        ] {
            let transport = Script::new(vec![response(200, body)]);
            let error = authenticate(&transport, number(), Instant::now() + DEADLINE)
                .err()
                .unwrap();
            assert_eq!(error, Error::InvalidResponse);
            assert!(!format!("{error:?} {error}").contains("secret"));
        }
    }

    #[test]
    fn devices_validate_and_match_only_supplied_public_key() {
        let bytes = format!(
            r#"[{{"id":"{ID}","name":"quiet fox","pubkey":"{KEY}","created":"2024-02-29T01:02:03.123Z"}}]"#
        );
        let matched = decode_devices(bytes.as_bytes(), KEY).unwrap();
        assert!(matched[0].current);
        assert!(!decode_devices(bytes.as_bytes(), OTHER_KEY).unwrap()[0].current);
        assert!(!serde_json::to_string(&matched)
            .unwrap()
            .contains("account_number"));
        let duplicates = format!(
            "[{},{}]",
            &bytes[1..bytes.len() - 1],
            &bytes[1..bytes.len() - 1]
        );
        assert_eq!(
            decode_devices(duplicates.as_bytes(), KEY).unwrap_err(),
            Error::InvalidResponse
        );
        for bad in [
            bytes.replace(ID, "../me"),
            bytes.replace("2024-02-29", "2023-02-29"),
            bytes.replace(KEY, "not-a-key"),
        ] {
            assert_eq!(
                decode_devices(bad.as_bytes(), KEY).unwrap_err(),
                Error::InvalidResponse
            );
        }
    }

    #[test]
    fn account_devices_read_without_identity_leaves_all_devices_unmatched() {
        let other_id = "fedcba98-7654-3210-fedc-ba9876543210";
        let devices = format!(
            r#"[{{"id":"{ID}","name":"current candidate","pubkey":"{KEY}","created":"2024-02-29T01:02:03Z"}},{{"id":"{other_id}","name":"other device","pubkey":"{OTHER_KEY}","created":"2024-02-29T01:02:03Z"}}]"#
        );

        let transport = Script::new(vec![
            response(401, "{}"),
            response(200, AUTH),
            response(200, ACCOUNT),
            response(200, &devices),
        ]);
        let deadline = Instant::now() + DEADLINE;
        let snapshot = read_account_inner(&transport, &mut session(), None, deadline).unwrap();
        assert_eq!(snapshot.devices.len(), 2);
        assert!(snapshot.devices.iter().all(|device| !device.current));
        let calls = transport.calls.borrow();
        assert_eq!(
            calls.iter().map(|call| call.method).collect::<Vec<_>>(),
            [Method::Get, Method::Post, Method::Get, Method::Get]
        );
        assert_eq!(
            calls
                .iter()
                .map(|call| call.path.as_str())
                .collect::<Vec<_>>(),
            [
                "accounts/v1/accounts/me",
                "auth/v1/token",
                "accounts/v1/accounts/me",
                "accounts/v1/devices",
            ]
        );
        assert!(calls.iter().all(|call| call.deadline == deadline));

        let transport = Script::new(vec![response(200, ACCOUNT), response(200, &devices)]);
        let keyed =
            read_account(&transport, &mut session(), KEY, Instant::now() + DEADLINE).unwrap();
        assert!(keyed.devices[0].current);
        assert!(!keyed.devices[1].current);

        let transport = Script::new(vec![response(200, ACCOUNT), Err(Error::Unreachable)]);
        assert_eq!(
            read_account_inner(&transport, &mut session(), None, Instant::now() + DEADLINE,)
                .unwrap_err(),
            Error::Unreachable
        );
        assert_eq!(transport.calls.borrow().len(), 2);
    }

    #[test]
    fn definite_get_401_renews_once_with_one_total_deadline() {
        let transport = Script::new(vec![
            response(401, "{}"),
            response(200, AUTH),
            response(200, ACCOUNT),
            response(200, "[]"),
        ]);
        let deadline = Instant::now() + DEADLINE;
        let result = read_account(&transport, &mut session(), KEY, deadline).unwrap();
        assert!(result.devices.is_empty());
        let calls = transport.calls.borrow();
        assert_eq!(
            calls.iter().map(|c| c.method).collect::<Vec<_>>(),
            [Method::Get, Method::Post, Method::Get, Method::Get]
        );
        assert!(calls.iter().all(|c| c.deadline == deadline));
    }

    #[test]
    fn second_get_401_does_not_renew_again_or_emit_partial_snapshot() {
        let transport = Script::new(vec![
            response(401, "{}"),
            response(200, AUTH),
            response(200, ACCOUNT),
            response(401, "{}"),
        ]);
        let error =
            read_account(&transport, &mut session(), KEY, Instant::now() + DEADLINE).unwrap_err();
        assert_eq!(error.code(), "invalid_access_token");
        assert_eq!(transport.calls.borrow().len(), 4);
    }

    #[test]
    fn ambiguous_get_failure_is_never_retried() {
        let transport = Script::new(vec![Err(Error::Unreachable)]);
        assert_eq!(
            read_account(&transport, &mut session(), KEY, Instant::now() + DEADLINE).unwrap_err(),
            Error::Unreachable
        );
        assert_eq!(transport.calls.borrow().len(), 1);
    }

    #[test]
    fn mutation_unknown_requires_reconciliation_and_never_retries() {
        for reply in [
            Err(Error::Unreachable),
            Err(Error::DeadlineExceeded),
            Err(Error::ResponseTooLarge),
            response(500, "{}"),
            response(408, "{}"),
            response(302, "{}"),
            response(200, "{}"),
        ] {
            let transport = Script::new(vec![reply]);
            let error = remove_device(
                &transport,
                &session(),
                &DeviceId::new(ID.into()).unwrap(),
                Instant::now() + DEADLINE,
            )
            .unwrap_err();
            assert!(error.requires_reconciliation());
            assert_eq!(transport.calls.borrow().len(), 1);
        }
        let transport = Script::new(vec![response(401, r#"{"code":"INVALID_ACCESS_TOKEN"}"#)]);
        assert_eq!(
            remove_device(
                &transport,
                &session(),
                &DeviceId::new(ID.into()).unwrap(),
                Instant::now() + DEADLINE
            )
            .unwrap_err()
            .code(),
            "invalid_access_token"
        );
        assert_eq!(transport.calls.borrow().len(), 1);
        let transport = Script::new(vec![response(204, "")]);
        assert!(remove_device(
            &transport,
            &session(),
            &DeviceId::new(ID.into()).unwrap(),
            Instant::now() + DEADLINE
        )
        .is_ok());
    }

    #[test]
    fn voucher_receipt_and_rejection_are_typed_but_malformed_success_is_unknown() {
        let transport = Script::new(vec![response(
            200,
            r#"{"time_added":100,"new_expiry":"2030-01-01T00:00:00Z"}"#,
        )]);
        assert_eq!(
            redeem_voucher(
                &transport,
                &session(),
                VoucherCode::new("Abcd1234".into()).unwrap(),
                Instant::now() + DEADLINE
            )
            .unwrap()
            .time_added,
            100
        );
        for body in [
            "malformed secret body",
            "{}",
            r#"{"time_added":0,"new_expiry":"2030-01-01T00:00:00Z"}"#,
        ] {
            let transport = Script::new(vec![response(200, body)]);
            assert_eq!(
                redeem_voucher(
                    &transport,
                    &session(),
                    VoucherCode::new("Abcd1234".into()).unwrap(),
                    Instant::now() + DEADLINE
                )
                .unwrap_err(),
                Error::OutcomeUnknown
            );
        }
        for (code, reason) in [
            ("INVALID_VOUCHER", Rejection::InvalidVoucher),
            ("VOUCHER_USED", Rejection::VoucherUsed),
            ("DEVICE_NOT_FOUND", Rejection::DeviceNotFound),
        ] {
            let response = response(
                400,
                &format!(r#"{{"code":"{code}","detail":"sensitive echoed input"}}"#),
            )
            .unwrap();
            let error = require_success(&response, true, &[200]).unwrap_err();
            assert_eq!(
                error,
                Error::Rejected {
                    status: 400,
                    reason
                }
            );
            assert!(!format!("{error:?} {error}").contains("sensitive"));
        }
    }

    fn created_device_json(id: &str, key: &str, ipv4: &str, ipv6: &str) -> String {
        format!(
            r#"{{"id":"{id}","name":"quiet fox","pubkey":"{key}","created":"2024-02-29T01:02:03Z","ipv4_address":"{ipv4}","ipv6_address":"{ipv6}","hijack_dns":false}}"#
        )
    }

    #[test]
    fn create_device_uses_official_post_contract_and_returns_assigned_addresses() {
        let body = created_device_json(ID, KEY, "10.64.0.2/32", "fc00:bbbb:bbbb:bb01::2/128");
        let transport = Script::new(vec![response(201, &body)]);
        let created =
            create_device(&transport, &session(), KEY, Instant::now() + DEADLINE).unwrap();

        assert_eq!(created.device.id.as_str(), ID);
        assert_eq!(created.device.pubkey, KEY);
        assert!(created.device.current);
        assert_eq!(created.addresses.ipv4_address, "10.64.0.2/32");
        assert_eq!(created.addresses.ipv6_address, "fc00:bbbb:bbbb:bb01::2/128");
        let calls = transport.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].method, Method::Post);
        assert_eq!(calls[0].path, "accounts/v1/devices");
        assert!(calls[0].has_token);
        let payload: serde_json::Value =
            serde_json::from_str(calls[0].body.as_deref().unwrap()).unwrap();
        assert_eq!(payload["pubkey"], KEY);
        assert_eq!(payload["hijack_dns"], false);
        assert_eq!(payload.as_object().unwrap().len(), 2);
        assert!(calls[0].deadline > Instant::now());
    }

    #[test]
    fn create_device_rejects_invalid_keys_without_sending_and_unknown_results_never_retry() {
        let transport = Script::new(vec![]);
        assert_eq!(
            create_device(
                &transport,
                &session(),
                "not-a-32-byte-key",
                Instant::now() + DEADLINE,
            )
            .unwrap_err(),
            Error::InvalidPublicKey
        );
        assert!(transport.calls.borrow().is_empty());

        let invalid_responses = vec![
            "malformed response".to_owned(),
            "{}".to_owned(),
            created_device_json("../id", KEY, "10.64.0.2/32", "fc00:bbbb:bbbb:bb01::2/128"),
            created_device_json(ID, OTHER_KEY, "10.64.0.2/32", "fc00:bbbb:bbbb:bb01::2/128"),
            created_device_json(ID, KEY, "10.64.0.2/24", "fc00:bbbb:bbbb:bb01::2/128"),
            created_device_json(ID, KEY, "127.0.0.1/32", "fc00:bbbb:bbbb:bb01::2/128"),
            created_device_json(ID, KEY, "10.64.0.2/32", "fe80::2/128"),
            created_device_json(ID, KEY, "10.64.0.2/32", "fc00:bbbb:bbbb:bb01::2/127"),
            created_device_json(ID, KEY, "10.64.0.2/32", "::ffff:192.0.2.1/128"),
        ];
        let unknowns = [
            Err(Error::Unreachable),
            Err(Error::DeadlineExceeded),
            response(500, "{}"),
            response(408, "{}"),
            response(302, "{}"),
            response(200, "{}"),
            response(201, &invalid_responses[0]),
            response(201, &invalid_responses[1]),
            response(201, &invalid_responses[2]),
            response(201, &invalid_responses[3]),
            response(201, &invalid_responses[4]),
            response(201, &invalid_responses[5]),
            response(201, &invalid_responses[6]),
            response(201, &invalid_responses[7]),
            response(201, &invalid_responses[8]),
        ];
        for reply in unknowns {
            let transport = Script::new(vec![reply]);
            let error =
                create_device(&transport, &session(), KEY, Instant::now() + DEADLINE).unwrap_err();
            assert_eq!(error, Error::OutcomeUnknown);
            assert!(error.requires_reconciliation());
            assert_eq!(transport.calls.borrow().len(), 1);
        }
    }

    #[test]
    fn replace_device_key_uses_official_put_contract_and_checks_response_identity() {
        let body = created_device_json(ID, OTHER_KEY, "10.64.0.9/32", "fc00:bbbb:bbbb:bb01::9/128");
        let transport = Script::new(vec![response(200, &body)]);
        let addresses = replace_device_key(
            &transport,
            &session(),
            &DeviceId::new(ID.into()).unwrap(),
            OTHER_KEY,
            Instant::now() + DEADLINE,
        )
        .unwrap();
        assert_eq!(addresses.ipv4_address, "10.64.0.9/32");
        assert_eq!(addresses.ipv6_address, "fc00:bbbb:bbbb:bb01::9/128");
        let calls = transport.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].method, Method::Put);
        assert_eq!(calls[0].path, format!("accounts/v1/devices/{ID}/pubkey"));
        assert!(calls[0].has_token);
        let payload: serde_json::Value =
            serde_json::from_str(calls[0].body.as_deref().unwrap()).unwrap();
        assert_eq!(payload["pubkey"], OTHER_KEY);
        assert_eq!(payload.as_object().unwrap().len(), 1);

        for bad in [
            created_device_json(
                "fedcba98-7654-3210-fedc-ba9876543210",
                OTHER_KEY,
                "10.64.0.9/32",
                "fc00:bbbb:bbbb:bb01::9/128",
            ),
            created_device_json(ID, KEY, "10.64.0.9/32", "fc00:bbbb:bbbb:bb01::9/128"),
            created_device_json(ID, OTHER_KEY, "0.0.0.0/32", "fc00:bbbb:bbbb:bb01::9/128"),
            created_device_json(ID, OTHER_KEY, "127.0.0.1/32", "fc00:bbbb:bbbb:bb01::9/128"),
            created_device_json(ID, OTHER_KEY, "10.64.0.9/32", "ff02::1/128"),
            created_device_json(ID, OTHER_KEY, "10.64.0.9/32", "::ffff:192.0.2.1/128"),
        ] {
            let transport = Script::new(vec![response(200, &bad)]);
            assert_eq!(
                replace_device_key(
                    &transport,
                    &session(),
                    &DeviceId::new(ID.into()).unwrap(),
                    OTHER_KEY,
                    Instant::now() + DEADLINE,
                )
                .unwrap_err(),
                Error::OutcomeUnknown
            );
            assert_eq!(transport.calls.borrow().len(), 1);
        }
    }

    #[test]
    fn key_replacement_rejection_is_definite_but_transport_unknown_is_not_retried() {
        let transport = Script::new(vec![response(
            400,
            r#"{"code":"PUBKEY_IN_USE","detail":"private details stay hidden"}"#,
        )]);
        let error = replace_device_key(
            &transport,
            &session(),
            &DeviceId::new(ID.into()).unwrap(),
            OTHER_KEY,
            Instant::now() + DEADLINE,
        )
        .unwrap_err();
        assert_eq!(
            error,
            Error::Rejected {
                status: 400,
                reason: Rejection::PublicKeyInUse,
            }
        );
        assert!(!format!("{error:?} {error}").contains("private details"));
        assert_eq!(transport.calls.borrow().len(), 1);

        for reply in [
            Err(Error::Unreachable),
            Err(Error::DeadlineExceeded),
            response(500, "{}"),
            response(408, "{}"),
            response(302, "{}"),
            response(200, "malformed response"),
        ] {
            let transport = Script::new(vec![reply]);
            let error = replace_device_key(
                &transport,
                &session(),
                &DeviceId::new(ID.into()).unwrap(),
                OTHER_KEY,
                Instant::now() + DEADLINE,
            )
            .unwrap_err();
            assert_eq!(error, Error::OutcomeUnknown);
            assert!(error.requires_reconciliation());
            assert_eq!(transport.calls.borrow().len(), 1);
        }
    }

    #[test]
    fn timestamps_are_calendar_checked_and_bounded() {
        for value in [
            "2030-01-01T00:00:00Z",
            "2024-02-29T12:30:12.123456789+01:00",
        ] {
            assert!(valid_timestamp(value));
        }
        for value in [
            "",
            "2030-13-01T00:00:00Z",
            "2030-02-30T00:00:00Z",
            "2030-01-01T24:00:00Z",
            "2030-01-01T00:00:00.Z",
            "2030-01-01T00:00:00Zextra",
            "2030-01-01T00:00:00+24:00",
        ] {
            assert!(!valid_timestamp(value));
        }
    }

    #[test]
    fn slow_proxy_negotiation_obeys_the_remaining_request_budget() {
        // The proxy rejects CONNECT after a delay. No TLS bypass or real API
        // call: distinguish a received proxy rejection from an early timeout.
        for (delay, budget, expected) in [
            (
                Duration::from_millis(4200),
                Duration::from_secs(6),
                Error::ProxyConnectFailed,
            ),
            (
                Duration::from_millis(300),
                Duration::from_millis(100),
                Error::DeadlineExceeded,
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                use std::io::Write;
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    assert!(request.len() < 2048);
                    let mut byte = [0u8];
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                std::thread::sleep(delay);
                let _ = stream.write_all(
                    b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            });
            let transport = HttpTransport::new(BootstrapProxy::new(address).unwrap()).unwrap();
            let error = transport
                .request(
                    Method::Get,
                    "accounts/v1/devices",
                    None,
                    None,
                    Instant::now() + budget,
                    ACCOUNT_BODY_CAP,
                )
                .err()
                .unwrap();
            assert_eq!(error, expected);
            server.join().unwrap();
        }
    }

    #[test]
    fn real_transport_uses_loopback_connect_and_rejects_proxy_redirect() {
        // This is a local CONNECT boundary test. No TLS success/account call is
        // simulated as official acceptance and api.mullvad.net is never contacted.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            use std::io::Write;
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                assert!(request.len() < 2048);
                let mut byte = [0u8];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let request = std::str::from_utf8(&request).unwrap();
            assert!(request.starts_with("CONNECT api.mullvad.net:443 HTTP/1.1\r\n"));
            stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        });
        let client = MullvadClient::new(BootstrapProxy::new(address).unwrap()).unwrap();
        assert!(client.fetch_relays().is_err());
        server.join().unwrap();
    }
}
