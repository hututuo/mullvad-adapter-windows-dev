//! Explicit import of an existing WireGuard device identity, never registration.
//!
//! The host owns authorization and its transaction lock across store commit,
//! read-back and publication. Account logout must not call `clear_identity`.
//! Clearing/replacing an identity while a worker uses it must be blocked by the
//! host. This module does not inspect backup paths or alter remote devices.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::{
    fmt, io,
    net::{Ipv4Addr, Ipv6Addr},
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Includes ignored legacy data. Bounds parsing and serializer memory as well.
pub const MAX_IDENTITY_JSON: usize = 16 * 1024;
const STORAGE_SCHEMA: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IdentityMetadata {
    pub device_id: String,
    pub device_name: String,
    pub public_key: String,
    pub ipv4_address: Ipv4Addr,
    pub ipv6_address: Ipv6Addr,
}

/// Opaque owned secret. No Debug, Clone, Serialize, Deref or private-key accessor.
///
/// Plaintext borrowing is only possible inside the explicit engine closure.
/// The closure must produce an engine-owned secret configuration, not a log or
/// ordinary snapshot. An authorized caller can deliberately copy plaintext;
/// the type cannot prevent that, nor erase its caller's original input buffer.
pub struct TunnelIdentity {
    metadata: IdentityMetadata,
    private_key: Zeroizing<String>,
}

/// Cannot be constructed outside this module. Only delivered to the engine
/// closure, and it has no formatting or serialization implementation.
pub struct EngineIdentityRef<'a> {
    pub private_key: &'a str,
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
}

impl TunnelIdentity {
    /// Takes ownership of the user's explicitly supplied JSON buffer. There is
    /// no filesystem discovery and no generation or registration of a new key.
    pub fn from_backup_json(json: String) -> Result<Self, IdentityError> {
        let json = Zeroizing::new(json);
        parse_backup(json.as_bytes())
    }

    /// Only the host's explicit, confirmed local key-view command may call this.
    /// The returned secret must not enter dashboard, log, diagnostic or receipt caches.
    pub(crate) fn reveal_for_local_view(&self) -> Zeroizing<String> {
        Zeroizing::new(self.private_key.to_string())
    }

    pub fn metadata(&self) -> &IdentityMetadata {
        &self.metadata
    }

    pub fn with_engine_identity<R>(
        &self,
        action: impl for<'a> FnOnce(EngineIdentityRef<'a>) -> R,
    ) -> R {
        action(EngineIdentityRef {
            private_key: &self.private_key,
            ipv4: self.metadata.ipv4_address,
            ipv6: self.metadata.ipv6_address,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityError {
    PayloadTooLarge,
    InvalidJson,
    InvalidDeviceId,
    InvalidDeviceName,
    InvalidPrivateKey,
    InvalidPublicKey,
    PublicKeyMismatch,
    InvalidIpv4Address,
    InvalidIpv6Address,
    UnsupportedStorageSchema,
    StoreWriteFailed,
    StoreReadFailed,
    ReadBackMismatch,
    BackupOccupied,
}
impl IdentityError {
    pub fn code(self) -> &'static str {
        match self {
            Self::PayloadTooLarge => "identity_payload_too_large",
            Self::InvalidJson => "identity_invalid_json",
            Self::InvalidDeviceId => "identity_invalid_device_id",
            Self::InvalidDeviceName => "identity_invalid_device_name",
            Self::InvalidPrivateKey => "identity_invalid_private_key",
            Self::InvalidPublicKey => "identity_invalid_public_key",
            Self::PublicKeyMismatch => "identity_public_key_mismatch",
            Self::InvalidIpv4Address => "identity_invalid_ipv4_address",
            Self::InvalidIpv6Address => "identity_invalid_ipv6_address",
            Self::UnsupportedStorageSchema => "identity_unsupported_storage_schema",
            Self::StoreWriteFailed => "identity_store_write_failed",
            Self::StoreReadFailed => "identity_store_read_failed",
            Self::ReadBackMismatch => "identity_store_readback_mismatch",
            Self::BackupOccupied => "identity_backup_occupied",
        }
    }
}
impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for IdentityError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportedIdentity {
    device_id: String,
    device_name: String,
    public_key: String,
    #[serde(deserialize_with = "decode_secret")]
    private_key: Zeroizing<String>,
    ipv4_address: String,
    ipv6_address: String,
    // Serde skips this value, including nested fields, without retaining the
    // previous key, account number or any other historical backup content.
    #[serde(default)]
    replaced_from: Option<serde::de::IgnoredAny>,
    // Existing backups may carry this informational timestamp. It is not a
    // credential or engine input, and no value from it is retained.
    #[serde(default)]
    registered_at: Option<serde::de::IgnoredAny>,
}

fn decode_secret<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}

fn parse_backup(bytes: &[u8]) -> Result<TunnelIdentity, IdentityError> {
    require_bound(bytes)?;
    let imported = serde_json::from_slice(bytes).map_err(|_| IdentityError::InvalidJson)?;
    validate(imported)
}

fn require_bound(bytes: &[u8]) -> Result<(), IdentityError> {
    if bytes.len() > MAX_IDENTITY_JSON {
        return Err(IdentityError::PayloadTooLarge);
    }
    Ok(())
}

fn validate(input: ImportedIdentity) -> Result<TunnelIdentity, IdentityError> {
    let id = input.device_id;
    if id.len() != 36
        || !id.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
        || id.bytes().all(|b| b == b'0' || b == b'-')
    {
        return Err(IdentityError::InvalidDeviceId);
    }
    if input.device_name.is_empty()
        || input.device_name.len() > 128
        || input.device_name.trim() != input.device_name
        || input.device_name.chars().any(char::is_control)
    {
        return Err(IdentityError::InvalidDeviceName);
    }

    let private_bytes =
        decode_key(&input.private_key).map_err(|_| IdentityError::InvalidPrivateKey)?;
    if private_bytes.iter().all(|b| *b == 0) {
        return Err(IdentityError::InvalidPrivateKey);
    }
    let supplied_public =
        decode_key(&input.public_key).map_err(|_| IdentityError::InvalidPublicKey)?;
    let private = StaticSecret::from(*private_bytes);
    let derived = PublicKey::from(&private);
    if !equal_secret(derived.as_bytes(), &*supplied_public) {
        return Err(IdentityError::PublicKeyMismatch);
    }
    let ipv4 = parse_v4(&input.ipv4_address)?;
    let ipv6 = parse_v6(&input.ipv6_address)?;
    // Only current fields reach the resulting identity; replaced_from is dropped.
    let _ = input.replaced_from;
    let _ = input.registered_at;
    Ok(TunnelIdentity {
        metadata: IdentityMetadata {
            device_id: id.to_ascii_lowercase(),
            device_name: input.device_name,
            public_key: input.public_key,
            ipv4_address: ipv4,
            ipv6_address: ipv6,
        },
        private_key: input.private_key,
    })
}

fn decode_key(text: &str) -> Result<Zeroizing<[u8; 32]>, ()> {
    if text.len() != 44 || !text.ends_with('=') {
        return Err(());
    }
    let mut bytes = Zeroizing::new([0; 32]);
    if STANDARD
        .decode_slice(text.as_bytes(), &mut *bytes)
        .map_err(|_| ())?
        != 32
    {
        return Err(());
    }
    Ok(bytes)
}

fn host_ip(text: &str, prefix: u8) -> Result<&str, ()> {
    if let Some((ip, mask)) = text.split_once('/') {
        if !matches!((prefix, mask), (32, "32") | (128, "128")) {
            return Err(());
        }
        Ok(ip)
    } else {
        Ok(text)
    }
}
fn parse_v4(text: &str) -> Result<Ipv4Addr, IdentityError> {
    let ip = host_ip(text, 32)
        .map_err(|_| IdentityError::InvalidIpv4Address)?
        .parse::<Ipv4Addr>()
        .map_err(|_| IdentityError::InvalidIpv4Address)?;
    // Mullvad's inner IPv4 interface address is private 10/8. An endpoint,
    // wildcard, hostname, loopback or a routed network is not an interface ID.
    if ip.octets()[0] != 10 {
        return Err(IdentityError::InvalidIpv4Address);
    }
    Ok(ip)
}
fn parse_v6(text: &str) -> Result<Ipv6Addr, IdentityError> {
    let ip = host_ip(text, 128)
        .map_err(|_| IdentityError::InvalidIpv6Address)?
        .parse::<Ipv6Addr>()
        .map_err(|_| IdentityError::InvalidIpv6Address)?;
    if ip.segments()[0] & 0xfe00 != 0xfc00 {
        return Err(IdentityError::InvalidIpv6Address);
    }
    Ok(ip)
}
fn equal_secret(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .fold(0, |difference, (x, y)| difference | (x ^ y))
            == 0
}

#[derive(Serialize)]
struct StoredIdentityRef<'a> {
    device_id: &'a str,
    device_name: &'a str,
    public_key: &'a str,
    private_key: &'a str,
    ipv4_address: String,
    ipv6_address: String,
}
#[derive(Serialize)]
struct StoredRecordRef<'a> {
    schema: u8,
    identity: Option<StoredIdentityRef<'a>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRecord {
    schema: u8,
    // An absent identity field is corruption, not a deliberate null tombstone.
    #[serde(deserialize_with = "decode_optional_identity")]
    identity: Option<ImportedIdentity>,
}
fn decode_optional_identity<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<ImportedIdentity>, D::Error> {
    Option::deserialize(d)
}

fn encode_record(identity: Option<&TunnelIdentity>) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
    let record = StoredRecordRef {
        schema: STORAGE_SCHEMA,
        identity: identity.map(|id| StoredIdentityRef {
            device_id: &id.metadata.device_id,
            device_name: &id.metadata.device_name,
            public_key: &id.metadata.public_key,
            private_key: &id.private_key,
            ipv4_address: id.metadata.ipv4_address.to_string(),
            ipv6_address: id.metadata.ipv6_address.to_string(),
        }),
    };
    // One fixed allocation prevents old secret bytes surviving a Vec reallocation.
    let mut output = Zeroizing::new(Vec::with_capacity(MAX_IDENTITY_JSON));
    serde_json::to_writer(&mut *output, &record).map_err(|_| IdentityError::InvalidJson)?;
    require_bound(&output)?;
    Ok(output)
}

fn decode_record(bytes: &[u8]) -> Result<Option<TunnelIdentity>, IdentityError> {
    require_bound(bytes)?;
    let record: StoredRecord =
        serde_json::from_slice(bytes).map_err(|_| IdentityError::InvalidJson)?;
    if record.schema != STORAGE_SCHEMA {
        return Err(IdentityError::UnsupportedStorageSchema);
    }
    record.identity.map(validate).transpose()
}

/// Preserve the previous identity before an explicitly confirmed replacement.
/// A different valid backup is archived as ciphertext before advancing the fixed
/// backup. Corrupt/unreadable archives fail closed; unique key material is retained.
#[cfg(any(windows, feature = "windows-api-check"))]
pub(crate) fn preserve_previous(
    store: &adapter_platform::windows_store::PrivateStore,
    proposed: &TunnelIdentity,
) -> Result<(), IdentityError> {
    use adapter_platform::storage_record::RecordKind;
    let Some(previous) = load_identity(store)? else {
        return Ok(());
    };
    if previous.metadata == proposed.metadata
        && equal_secret(
            previous.private_key.as_bytes(),
            proposed.private_key.as_bytes(),
        )
    {
        return Ok(());
    }
    match store.load(RecordKind::IdentityBackup) {
        Ok(record) => {
            let backup = decode_record(record.expose())?.ok_or(IdentityError::ReadBackMismatch)?;
            if backup.metadata == previous.metadata
                && equal_secret(
                    backup.private_key.as_bytes(),
                    previous.private_key.as_bytes(),
                )
            {
                return Ok(());
            }
            store
                .archive(RecordKind::IdentityBackup)
                .map_err(|_| IdentityError::StoreWriteFailed)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(IdentityError::StoreReadFailed),
    }
    let encoded = encode_record(Some(&previous))?;
    store
        .prepare(RecordKind::IdentityBackup, &encoded)
        .map_err(|_| IdentityError::StoreWriteFailed)?
        .commit()
        .map_err(|_| IdentityError::StoreWriteFailed)?;
    let record = store
        .load(RecordKind::IdentityBackup)
        .map_err(|_| IdentityError::StoreReadFailed)?;
    let backup = decode_record(record.expose())?.ok_or(IdentityError::ReadBackMismatch)?;
    if backup.metadata != previous.metadata
        || !equal_secret(
            backup.private_key.as_bytes(),
            previous.private_key.as_bytes(),
        )
    {
        return Err(IdentityError::ReadBackMismatch);
    }
    Ok(())
}

// This narrow seam tests the real transaction ordering without providing public
// plaintext export APIs or replacing the production DPAPI storage policy.
trait IdentityBackend {
    fn write(&self, payload: &[u8]) -> io::Result<()>;
    fn read(&self) -> io::Result<Option<Zeroizing<Vec<u8>>>>;
}

fn persist_with(
    backend: &impl IdentityBackend,
    identity: &TunnelIdentity,
) -> Result<TunnelIdentity, IdentityError> {
    // A new explicit import is not permission to repair/delete a corrupt or
    // future-schema stored identity. Preserve that evidence for a separate
    // recovery transaction, just as PrivateStore preserves invalid envelopes.
    drop(load_with(backend)?);
    let encoded = encode_record(Some(identity))?;
    backend
        .write(&encoded)
        .map_err(|_| IdentityError::StoreWriteFailed)?;
    let reloaded = load_with(backend)?.ok_or(IdentityError::ReadBackMismatch)?;
    if reloaded.metadata != identity.metadata
        || !equal_secret(
            reloaded.private_key.as_bytes(),
            identity.private_key.as_bytes(),
        )
    {
        return Err(IdentityError::ReadBackMismatch);
    }
    Ok(reloaded)
}
fn load_with(backend: &impl IdentityBackend) -> Result<Option<TunnelIdentity>, IdentityError> {
    backend
        .read()
        .map_err(|_| IdentityError::StoreReadFailed)?
        .map(|bytes| decode_record(&bytes))
        .transpose()
        .map(Option::flatten)
}
fn clear_with(backend: &impl IdentityBackend) -> Result<(), IdentityError> {
    drop(load_with(backend)?);
    let tombstone = encode_record(None)?;
    backend
        .write(&tombstone)
        .map_err(|_| IdentityError::StoreWriteFailed)?;
    // Absence alone is insufficient: this exact store must read back the committed
    // versioned tombstone. No raw-path deletion or removal of other record kinds.
    let stored = backend
        .read()
        .map_err(|_| IdentityError::StoreReadFailed)?
        .ok_or(IdentityError::ReadBackMismatch)?;
    if decode_record(&stored)?.is_some() || !equal_secret(&stored, &tombstone) {
        return Err(IdentityError::ReadBackMismatch);
    }
    Ok(())
}

#[cfg(any(windows, feature = "windows-api-check"))]
struct WindowsIdentityBackend<'a>(&'a adapter_platform::windows_store::PrivateStore);
#[cfg(any(windows, feature = "windows-api-check"))]
impl IdentityBackend for WindowsIdentityBackend<'_> {
    fn write(&self, payload: &[u8]) -> io::Result<()> {
        self.0
            .prepare(
                adapter_platform::storage_record::RecordKind::Identity,
                payload,
            )?
            .commit()
    }
    fn read(&self) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        match self
            .0
            .load(adapter_platform::storage_record::RecordKind::Identity)
        {
            Ok(value) => Ok(Some(Zeroizing::new(value.expose().to_vec()))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
}

/// Returns the semantically validated read-back identity. Do not publish the
/// supplied identity before success; a failed read-back requires reconciliation.
#[cfg(any(windows, feature = "windows-api-check"))]
pub fn persist_identity(
    store: &adapter_platform::windows_store::PrivateStore,
    identity: &TunnelIdentity,
) -> Result<TunnelIdentity, IdentityError> {
    persist_with(&WindowsIdentityBackend(store), identity)
}

#[cfg(any(windows, feature = "windows-api-check"))]
pub fn load_identity(
    store: &adapter_platform::windows_store::PrivateStore,
) -> Result<Option<TunnelIdentity>, IdentityError> {
    load_with(&WindowsIdentityBackend(store))
}

/// Explicit identity removal, implemented as a read-back-verified DPAPI tombstone.
/// This is separate from account logout and must be blocked for active workers.
#[cfg(any(windows, feature = "windows-api-check"))]
pub fn clear_identity(
    store: &adapter_platform::windows_store::PrivateStore,
) -> Result<(), IdentityError> {
    clear_with(&WindowsIdentityBackend(store))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    const ID: &str = "01234567-89ab-cdef-0123-456789abcdef";
    fn from_hex(text: &str) -> [u8; 32] {
        std::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
    }
    // RFC 7748 Alice example, never a user identity or a live test key.
    fn private_key() -> String {
        STANDARD.encode(from_hex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ))
    }
    fn public_key() -> String {
        STANDARD.encode(from_hex(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        ))
    }
    fn backup() -> String {
        format!(
            r#"{{"device_id":"{ID}","device_name":"synthetic fox","public_key":"{}","private_key":"{}","ipv4_address":"10.77.1.2/32","ipv6_address":"fc00:bbbb:bbbb:bb01::1:2/128"}}"#,
            public_key(),
            private_key()
        )
    }
    fn identity() -> TunnelIdentity {
        TunnelIdentity::from_backup_json(backup()).unwrap()
    }

    struct MemoryBackend {
        value: RefCell<Option<Zeroizing<Vec<u8>>>>,
        fail_write: Cell<bool>,
        fail_read: Cell<bool>,
        fail_read_on_call: Cell<Option<usize>>,
        replacement: RefCell<Option<Vec<u8>>>,
        writes: Cell<usize>,
        reads: Cell<usize>,
    }
    impl MemoryBackend {
        fn new() -> Self {
            Self {
                value: RefCell::new(None),
                fail_write: Cell::new(false),
                fail_read: Cell::new(false),
                fail_read_on_call: Cell::new(None),
                replacement: RefCell::new(None),
                writes: Cell::new(0),
                reads: Cell::new(0),
            }
        }
    }
    impl IdentityBackend for MemoryBackend {
        fn write(&self, payload: &[u8]) -> io::Result<()> {
            self.writes.set(self.writes.get() + 1);
            if self.fail_write.get() {
                return Err(io::Error::other("private detail must not escape"));
            }
            let value = self
                .replacement
                .borrow_mut()
                .take()
                .unwrap_or_else(|| payload.to_vec());
            *self.value.borrow_mut() = Some(Zeroizing::new(value));
            Ok(())
        }
        fn read(&self) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
            self.reads.set(self.reads.get() + 1);
            if self.fail_read.get() || self.fail_read_on_call.get() == Some(self.reads.get()) {
                return Err(io::Error::other("private read detail must not escape"));
            }
            Ok(self
                .value
                .borrow()
                .as_ref()
                .map(|v| Zeroizing::new(v.to_vec())))
        }
    }

    #[test]
    fn known_x25519_vector_is_checked_before_engine_borrow() {
        let imported = identity();
        assert_eq!(imported.metadata().public_key, public_key());
        assert_eq!(
            imported.metadata().ipv4_address,
            "10.77.1.2".parse::<Ipv4Addr>().unwrap()
        );
        imported.with_engine_identity(|view| {
            assert_eq!(view.private_key, private_key());
            assert_eq!(view.ipv4, imported.metadata().ipv4_address);
            assert_eq!(
                view.ipv6,
                "fc00:bbbb:bbbb:bb01::1:2".parse::<Ipv6Addr>().unwrap()
            );
        });
        let safe = serde_json::to_string(imported.metadata()).unwrap();
        assert!(!safe.contains("private_key"));
        assert!(!safe.contains(&private_key()));
    }

    #[test]
    fn backup_is_strict_bounded_and_ignores_only_legacy_replaced_from() {
        let json = backup();
        let with_old = format!("{},\"registered_at\":\"2026-01-01T00:00:00Z\",\"replaced_from\":{{\"private_key\":\"synthetic prior secret\",\"account\":\"old account\"}}}}", &json[..json.len()-1]);
        let imported = TunnelIdentity::from_backup_json(with_old).unwrap();
        let encoded = encode_record(Some(&imported)).unwrap();
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(!text.contains("replaced_from"));
        assert!(!text.contains("synthetic prior secret"));
        assert!(!text.contains("old account"));
        assert!(!text.contains("registered_at"));
        for json in [
            "".into(),
            format!("{json}{json}"),
            json.replace("\"device_name\":", "\"unknown_name\":"),
            format!(
                "{},\"private_key\":\"duplicate\"}}",
                &json[..json.len() - 1]
            ),
        ] {
            assert_eq!(
                TunnelIdentity::from_backup_json(json).err().unwrap(),
                IdentityError::InvalidJson
            );
        }
        assert_eq!(
            TunnelIdentity::from_backup_json("x".repeat(MAX_IDENTITY_JSON + 1))
                .err()
                .unwrap(),
            IdentityError::PayloadTooLarge
        );
    }

    #[test]
    fn zero_malformed_noncanonical_and_mismatched_keys_fail_closed() {
        let json = backup();
        for key in [
            STANDARD.encode([0; 32]),
            "not a secret key".into(),
            "x".repeat(45),
            private_key().trim_end_matches('=').into(),
        ] {
            assert_eq!(
                TunnelIdentity::from_backup_json(json.replace(&private_key(), &key))
                    .err()
                    .unwrap(),
                IdentityError::InvalidPrivateKey
            );
        }
        let other_public =
            STANDARD.encode(PublicKey::from(&StaticSecret::from([7; 32])).as_bytes());
        assert_eq!(
            TunnelIdentity::from_backup_json(json.replace(&public_key(), &other_public))
                .err()
                .unwrap(),
            IdentityError::PublicKeyMismatch
        );
        assert_eq!(
            TunnelIdentity::from_backup_json(json.replace(&public_key(), "bad public key"))
                .err()
                .unwrap(),
            IdentityError::InvalidPublicKey
        );
        let mut noncanonical = private_key().into_bytes();
        // Last sextet's low two bits must be zero; equal decoded bytes must not
        // permit an alternate textual secret representation.
        noncanonical[42] = b'p';
        assert_eq!(
            TunnelIdentity::from_backup_json(
                json.replace(&private_key(), &String::from_utf8(noncanonical).unwrap())
            )
            .err()
            .unwrap(),
            IdentityError::InvalidPrivateKey
        );
    }

    #[test]
    fn identity_metadata_rejects_missing_malformed_or_control_input() {
        let json = backup();
        for id in [
            "../identity",
            "00000000-0000-0000-0000-000000000000",
            "01234567-89ab-cdef-0123-456789abcdeg",
        ] {
            assert_eq!(
                TunnelIdentity::from_backup_json(json.replace(ID, id))
                    .err()
                    .unwrap(),
                IdentityError::InvalidDeviceId
            );
        }
        assert_eq!(
            TunnelIdentity::from_backup_json(json.replace(ID, &ID.to_uppercase()))
                .unwrap()
                .metadata()
                .device_id,
            ID
        );
        for name in ["", " name", "name ", "line\\nsecret"] {
            assert_eq!(
                TunnelIdentity::from_backup_json(json.replace("synthetic fox", name))
                    .err()
                    .unwrap(),
                IdentityError::InvalidDeviceName
            );
        }
        assert_eq!(
            TunnelIdentity::from_backup_json(json.replace("synthetic fox", &"x".repeat(129)))
                .err()
                .unwrap(),
            IdentityError::InvalidDeviceName
        );
    }

    #[test]
    fn wireguard_host_addresses_cannot_be_endpoint_or_network_routes() {
        for ip in ["10.64.0.1", "10.127.1.2/32"] {
            assert!(parse_v4(ip).is_ok());
        }
        for ip in ["fc00:bbbb:bbbb:bb01::1", "fdff::123/128"] {
            assert!(parse_v6(ip).is_ok());
        }
        for ip in [
            "0.0.0.0",
            "127.0.0.1",
            "192.168.1.1",
            "198.51.100.1",
            "169.254.1.1",
            "224.0.0.1",
            "10.77.1.2/24",
            "10.77.1.2/32/32",
            "example.com",
            "10.77.1.2:51820",
        ] {
            assert_eq!(parse_v4(ip).unwrap_err(), IdentityError::InvalidIpv4Address);
        }
        for ip in [
            "::",
            "::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "fc00::1/64",
            "[fc00::1]",
            "fc00::1%eth0",
            "fc00::1/128/128",
        ] {
            assert_eq!(parse_v6(ip).unwrap_err(), IdentityError::InvalidIpv6Address);
        }
    }

    #[test]
    fn persist_requires_commit_then_semantically_equal_readback() {
        let backend = MemoryBackend::new();
        let source = identity();
        let verified = persist_with(&backend, &source).unwrap();
        assert_eq!(backend.writes.get(), 1);
        assert_eq!(backend.reads.get(), 2);
        assert_eq!(verified.metadata(), source.metadata());
        assert!(equal_secret(
            verified.private_key.as_bytes(),
            source.private_key.as_bytes()
        ));
        let loaded = load_with(&backend).unwrap().unwrap();
        assert_eq!(loaded.metadata(), source.metadata());
        let empty = MemoryBackend::new();
        assert!(load_with(&empty).unwrap().is_none());
    }

    #[test]
    fn write_readback_failure_preserves_source_and_does_not_publish() {
        let backend = MemoryBackend::new();
        let source = identity();
        backend.fail_write.set(true);
        assert_eq!(
            persist_with(&backend, &source).err().unwrap(),
            IdentityError::StoreWriteFailed
        );
        assert_eq!(backend.reads.get(), 1);
        assert!(backend.value.borrow().is_none());
        backend.fail_write.set(false);
        backend.fail_read.set(true);
        assert_eq!(
            persist_with(&backend, &source).err().unwrap(),
            IdentityError::StoreReadFailed
        );
        assert_eq!(source.metadata().public_key, public_key());
        assert!(!format!(
            "{} {:?}",
            IdentityError::StoreReadFailed,
            IdentityError::StoreReadFailed
        )
        .contains("private read detail"));
        backend.fail_read.set(false);
        backend.fail_read_on_call.set(Some(backend.reads.get() + 2));
        // The pre-write load succeeds, commit completes, and only its read-back
        // fails. Neither this case nor pre-write failure publishes the source.
        assert_eq!(
            persist_with(&backend, &source).err().unwrap(),
            IdentityError::StoreReadFailed
        );
        assert!(backend.value.borrow().is_some());
        backend.fail_read_on_call.set(None);
        let replacement = backup().replace("synthetic fox", "other fixture");
        let replacement = TunnelIdentity::from_backup_json(replacement).unwrap();
        *backend.replacement.borrow_mut() =
            Some(encode_record(Some(&replacement)).unwrap().to_vec());
        assert_eq!(
            persist_with(&backend, &source).err().unwrap(),
            IdentityError::ReadBackMismatch
        );
        let mut equivalent_key =
            from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        equivalent_key[0] ^= 1; // Clamping makes this derive the same public key.
        let replacement = TunnelIdentity::from_backup_json(
            backup().replace(&private_key(), &STANDARD.encode(equivalent_key)),
        )
        .unwrap();
        assert_eq!(replacement.metadata(), source.metadata());
        *backend.replacement.borrow_mut() =
            Some(encode_record(Some(&replacement)).unwrap().to_vec());
        assert_eq!(
            persist_with(&backend, &source).err().unwrap(),
            IdentityError::ReadBackMismatch
        );
    }

    #[test]
    fn corrupted_or_future_storage_never_repairs_or_replaces_itself() {
        let backend = MemoryBackend::new();
        for payload in [
            b"invalid secret payload".to_vec(),
            b"{\"schema\":1}".to_vec(),
            b"{\"schema\":2,\"identity\":null}".to_vec(),
            b"{\"schema\":1,\"identity\":null,\"unknown\":true}".to_vec(),
        ] {
            *backend.value.borrow_mut() = Some(Zeroizing::new(payload));
            assert!(load_with(&backend).is_err());
            assert!(persist_with(&backend, &identity()).is_err());
            assert!(clear_with(&backend).is_err());
            assert_eq!(backend.writes.get(), 0);
        }
        assert_eq!(
            decode_record(b"{\"schema\":2,\"identity\":null}")
                .err()
                .unwrap(),
            IdentityError::UnsupportedStorageSchema
        );
    }

    #[test]
    fn activation_commit_readback_failure_fences_old_identity_and_preserves_durable_new() {
        let backend = MemoryBackend::new();
        let old =
            TunnelIdentity::from_backup_json(backup().replace("synthetic fox", "previous fixture"))
                .unwrap();
        let old = persist_with(&backend, &old).unwrap();
        let mut published = Some(old);
        let proposed = identity();
        backend.fail_read_on_call.set(Some(backend.reads.get() + 2));
        let result = crate::live_device::activation_commit(persist_with(&backend, &proposed));
        let code = result.err().unwrap();
        assert_eq!(code, crate::live_device::ACTIVATION_UNCERTAIN);
        assert!(crate::live_device::fence_uncertain_activation(
            code,
            &mut published
        ));
        assert!(published.is_none(), "old identity must no longer be usable");
        backend.fail_read_on_call.set(None);
        let durable = load_with(&backend).unwrap().unwrap();
        assert_eq!(durable.metadata(), proposed.metadata());
        // Explicit reconciliation can succeed without replacing the generated key.
        let reconciled =
            crate::live_device::activation_commit(persist_with(&backend, &proposed)).unwrap();
        assert_eq!(reconciled.metadata(), proposed.metadata());
    }

    #[test]
    fn definite_precommit_activation_errors_do_not_forget_existing_identity() {
        let mut published = Some(identity());
        assert!(!crate::live_device::fence_uncertain_activation(
            "device_not_registered",
            &mut published
        ));
        assert!(published.is_some());
    }

    #[test]
    fn explicit_clear_writes_tombstone_and_checks_exact_readback() {
        let backend = MemoryBackend::new();
        persist_with(&backend, &identity()).unwrap();
        clear_with(&backend).unwrap();
        assert!(load_with(&backend).unwrap().is_none());
        let stored = backend.value.borrow();
        assert_eq!(
            &**stored.as_ref().unwrap(),
            b"{\"schema\":1,\"identity\":null}"
        );
        assert!(!std::str::from_utf8(stored.as_ref().unwrap())
            .unwrap()
            .contains("private_key"));
        drop(stored);
        *backend.replacement.borrow_mut() =
            Some(encode_record(Some(&identity())).unwrap().to_vec());
        assert_eq!(
            clear_with(&backend).unwrap_err(),
            IdentityError::ReadBackMismatch
        );
    }

    #[test]
    fn errors_never_echo_secret_input() {
        let errors = [
            IdentityError::PayloadTooLarge,
            IdentityError::InvalidJson,
            IdentityError::InvalidPrivateKey,
            IdentityError::PublicKeyMismatch,
            IdentityError::StoreReadFailed,
            IdentityError::StoreWriteFailed,
            IdentityError::ReadBackMismatch,
        ];
        for error in errors {
            assert!(!format!("{error} {error:?}").contains(&private_key()));
            assert!(error.code().starts_with("identity_"));
        }
    }

    #[test]
    fn secret_types_have_no_debug_serialize_or_clone_implementation() {
        // Each helper has one inferable marker unless the forbidden trait is
        // implemented; adding that trait then makes this test fail to compile.
        trait DebugBoundary<A> {}
        impl<T: ?Sized> DebugBoundary<()> for T {}
        struct DebugMarker;
        impl<T: ?Sized + fmt::Debug> DebugBoundary<DebugMarker> for T {}
        fn no_debug<T: ?Sized, A>()
        where
            T: DebugBoundary<A>,
        {
        }
        no_debug::<TunnelIdentity, _>();
        no_debug::<EngineIdentityRef<'static>, _>();

        trait SerializeBoundary<A> {}
        impl<T: ?Sized> SerializeBoundary<()> for T {}
        struct SerializeMarker;
        impl<T: ?Sized + Serialize> SerializeBoundary<SerializeMarker> for T {}
        fn no_serialize<T: ?Sized, A>()
        where
            T: SerializeBoundary<A>,
        {
        }
        no_serialize::<TunnelIdentity, _>();
        no_serialize::<EngineIdentityRef<'static>, _>();

        trait CloneBoundary<A> {}
        impl<T: ?Sized> CloneBoundary<()> for T {}
        struct CloneMarker;
        impl<T: Clone> CloneBoundary<CloneMarker> for T {}
        fn no_clone<T: ?Sized, A>()
        where
            T: CloneBoundary<A>,
        {
        }
        no_clone::<TunnelIdentity, _>();
        no_clone::<EngineIdentityRef<'static>, _>();
    }

    #[cfg(windows)]
    #[test]
    fn subsequent_replacement_preserves_exact_older_backups() {
        use adapter_platform::{
            storage_record::RecordKind, windows::boot_id, windows_store::PrivateStore,
        };
        use sha2::Digest;
        struct Fixture(std::path::PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root =
            Fixture(std::env::temp_dir().join(format!("adapter-archive-{}", boot_id().unwrap())));
        let store = PrivateStore::open(&root.0).unwrap();
        let first = identity();
        let second =
            TunnelIdentity::from_backup_json(backup().replace("synthetic fox", "synthetic hare"))
                .unwrap();
        let third =
            TunnelIdentity::from_backup_json(backup().replace("synthetic fox", "synthetic owl"))
                .unwrap();
        persist_identity(&store, &first).unwrap();
        preserve_previous(&store, &second).unwrap();
        let encrypted = std::fs::read(root.0.join("identity-backup.dpapi")).unwrap();
        let digest = format!("{:x}", sha2::Sha256::digest(&encrypted));
        persist_identity(&store, &second).unwrap();
        preserve_previous(&store, &third).unwrap();
        let archived = store
            .load_archive(RecordKind::IdentityBackup, &digest)
            .unwrap();
        assert_eq!(
            decode_record(archived.expose()).unwrap().unwrap().metadata,
            first.metadata
        );
        let previous = store.load(RecordKind::IdentityBackup).unwrap();
        assert_eq!(
            decode_record(previous.expose()).unwrap().unwrap().metadata,
            second.metadata
        );
        assert_eq!(
            load_identity(&store).unwrap().unwrap().metadata,
            second.metadata
        );
        assert_eq!(
            std::fs::read(
                root.0
                    .join(format!("archive-identity-backup-{digest}.dpapi"))
            )
            .unwrap(),
            encrypted
        );
        drop(previous);
        drop(archived);
        drop(store);
    }
    #[cfg(windows)]
    #[test]
    fn equivalent_clamped_key_bytes_still_preserve_the_original_secret() {
        use adapter_platform::{
            storage_record::RecordKind, windows::boot_id, windows_store::PrivateStore,
        };
        struct Fixture(std::path::PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root =
            Fixture(std::env::temp_dir().join(format!("adapter-clamped-{}", boot_id().unwrap())));
        let store = PrivateStore::open(&root.0).unwrap();
        let first = identity();
        let mut raw = STANDARD.decode(private_key()).unwrap();
        raw[0] ^= 1;
        let proposed = TunnelIdentity::from_backup_json(
            backup().replace(&private_key(), &STANDARD.encode(raw)),
        )
        .unwrap();
        assert_eq!(first.metadata, proposed.metadata);
        persist_identity(&store, &first).unwrap();
        preserve_previous(&store, &proposed).unwrap();
        let previous = store.load(RecordKind::IdentityBackup).unwrap();
        let recovered = decode_record(previous.expose()).unwrap().unwrap();
        assert!(equal_secret(
            recovered.private_key.as_bytes(),
            first.private_key.as_bytes()
        ));
        assert!(!equal_secret(
            recovered.private_key.as_bytes(),
            proposed.private_key.as_bytes()
        ));
        drop(previous);
        drop(store);
    }
    #[cfg(windows)]
    #[test]
    fn current_user_dpapi_identity_roundtrip_and_explicit_tombstone() {
        use adapter_platform::windows::boot_id;
        use adapter_platform::windows_store::PrivateStore;
        struct OwnedFixture(std::path::PathBuf);
        impl Drop for OwnedFixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = OwnedFixture(
            std::env::temp_dir().join(format!("adapter-identity-test-{}", boot_id().unwrap())),
        );
        let store = PrivateStore::open(&root.0).unwrap();
        assert!(load_identity(&store).unwrap().is_none());
        let source = identity();
        let verified = persist_identity(&store, &source).unwrap();
        assert_eq!(verified.metadata(), source.metadata());
        assert!(equal_secret(
            verified.private_key.as_bytes(),
            source.private_key.as_bytes()
        ));
        // The fixed file is ciphertext; this is only a synthetic privacy check.
        let encrypted = std::fs::read(root.0.join("identity.dpapi")).unwrap();
        assert!(!encrypted
            .windows(private_key().len())
            .any(|window| window == private_key().as_bytes()));
        clear_identity(&store).unwrap();
        assert!(load_identity(&store).unwrap().is_none());
        assert!(root.0.join("identity.dpapi").exists());
        assert!(!root.0.join("account.dpapi").exists());
        drop(store);
    }
}
