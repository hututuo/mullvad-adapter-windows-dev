//! Explicit device provisioning. Persist the key before sending only its public half.
use crate::live_identity::TunnelIdentity;
use adapter_mullvad_api::{AccountSession, MullvadClient};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::io;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;
const CAP: usize = 16384;
/// A failed commit/readback cannot establish which identity is durable. The
/// owner must stop using its old in-memory identity until explicitly reconciled.
pub(crate) const ACTIVATION_UNCERTAIN: &str = "identity_activation_uncertain";

pub(crate) fn activation_commit<T>(
    result: Result<T, crate::live_identity::IdentityError>,
) -> Result<T, &'static str> {
    result.map_err(|_| ACTIVATION_UNCERTAIN)
}

pub(crate) fn fence_uncertain_activation<T>(code: &str, current: &mut Option<T>) -> bool {
    if code != ACTIVATION_UNCERTAIN {
        return false;
    }
    *current = None;
    true
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicDraft {
    pub state: String,
    pub public_key: String,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Draft {
    schema: u8,
    account: String,
    state: String,
    public_key: String,
    #[serde(deserialize_with = "secret")]
    private_key: Zeroizing<String>,
    device_id: Option<String>,
    device_name: Option<String>,
    ipv4: Option<String>,
    ipv6: Option<String>,
}
fn secret<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
trait Store {
    fn read(&self) -> io::Result<Option<Zeroizing<Vec<u8>>>>;
    fn write(&self, bytes: &[u8]) -> io::Result<()>;
}
fn encode(draft: &Draft) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(CAP));
    // Serialize borrowed fields so no intermediate plain private-key String is made.
    #[derive(Serialize)]
    struct Ref<'a> {
        schema: u8,
        account: &'a str,
        state: &'a str,
        public_key: &'a str,
        private_key: &'a str,
        device_id: &'a Option<String>,
        device_name: &'a Option<String>,
        ipv4: &'a Option<String>,
        ipv6: &'a Option<String>,
    }
    let value = Ref {
        schema: draft.schema,
        account: &draft.account,
        state: &draft.state,
        public_key: &draft.public_key,
        private_key: &draft.private_key,
        device_id: &draft.device_id,
        device_name: &draft.device_name,
        ipv4: &draft.ipv4,
        ipv6: &draft.ipv6,
    };
    serde_json::to_writer(&mut *bytes, &value).map_err(|_| "device_draft_invalid")?;
    if bytes.len() > CAP {
        return Err("device_draft_invalid");
    }
    Ok(bytes)
}
fn load(store: &impl Store) -> Result<Option<Draft>, &'static str> {
    let Some(bytes) = store.read().map_err(|_| "device_draft_unavailable")? else {
        return Ok(None);
    };
    if bytes.len() > CAP {
        return Err("device_draft_invalid");
    }
    let d: Draft = serde_json::from_slice(&bytes).map_err(|_| "device_draft_invalid")?;
    if d.schema != 1
        || d.account.len() != 64
        || !d.account.bytes().all(|b| b.is_ascii_hexdigit())
        || !matches!(
            d.state.as_str(),
            "prepared" | "submitted" | "unknown" | "created"
        )
    {
        return Err("device_draft_invalid");
    }
    let mut raw = Zeroizing::new([0u8; 32]);
    if STANDARD.decode_slice(&*d.private_key, &mut *raw).ok() != Some(32)
        || STANDARD.encode(PublicKey::from(&StaticSecret::from(*raw)).as_bytes()) != d.public_key
    {
        return Err("device_draft_invalid");
    }
    if d.state == "created" {
        let _ = identity(&d)?;
    }
    Ok(Some(d))
}
fn save(store: &impl Store, draft: &Draft) -> Result<(), &'static str> {
    let encoded = encode(draft)?;
    store
        .write(&encoded)
        .map_err(|_| "device_draft_write_failed")?;
    let loaded = load(store)?.ok_or("device_draft_readback_failed")?;
    let verified = encode(&loaded)?;
    if encoded.len() != verified.len()
        || encoded
            .iter()
            .zip(verified.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            != 0
    {
        return Err("device_draft_readback_failed");
    }
    Ok(())
}
fn public(d: &Draft) -> PublicDraft {
    PublicDraft {
        state: d.state.clone(),
        public_key: d.public_key.clone(),
        device_id: d.device_id.clone(),
        device_name: d.device_name.clone(),
    }
}
fn identity(d: &Draft) -> Result<TunnelIdentity, &'static str> {
    if d.state != "created" {
        return Err("device_creation_not_confirmed");
    }
    #[derive(Serialize)]
    struct Backup<'a> {
        device_id: &'a str,
        device_name: &'a str,
        public_key: &'a str,
        private_key: &'a str,
        ipv4_address: &'a str,
        ipv6_address: &'a str,
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(CAP));
    let backup = Backup {
        device_id: d.device_id.as_deref().ok_or("device_draft_invalid")?,
        device_name: d.device_name.as_deref().ok_or("device_draft_invalid")?,
        public_key: &d.public_key,
        private_key: &d.private_key,
        ipv4_address: d.ipv4.as_deref().ok_or("device_draft_invalid")?,
        ipv6_address: d.ipv6.as_deref().ok_or("device_draft_invalid")?,
    };
    serde_json::to_writer(&mut *bytes, &backup).map_err(|_| "device_draft_invalid")?;
    let input =
        String::from_utf8(std::mem::take(&mut *bytes)).map_err(|_| "device_draft_invalid")?;
    TunnelIdentity::from_backup_json(input).map_err(|e| e.code())
}
#[cfg(any(windows, feature = "windows-api-check"))]
impl Store for adapter_platform::windows_store::PrivateStore {
    fn read(&self) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        match self.load(adapter_platform::storage_record::RecordKind::DeviceDraft) {
            Ok(r) => Ok(Some(Zeroizing::new(r.expose().to_vec()))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn write(&self, bytes: &[u8]) -> io::Result<()> {
        self.prepare(
            adapter_platform::storage_record::RecordKind::DeviceDraft,
            bytes,
        )?
        .commit()
    }
}
#[cfg(any(windows, feature = "windows-api-check"))]
pub fn snapshot(
    store: &adapter_platform::windows_store::PrivateStore,
    session: &AccountSession,
) -> Result<Option<PublicDraft>, &'static str> {
    Ok(load(store)?
        .filter(|d| d.account == session.binding_fingerprint())
        .as_ref()
        .map(public))
}
// A completed draft is reusable until activation. Only a matching durable active
// identity proves completion, allowing an explicitly confirmed subsequent create
// (including another account) after preserving its encrypted draft. Pending or
// uncertain registrations must never be replaced by generating another key.
fn replace_completed(
    draft: &Draft,
    binding: &str,
    active_key: Option<&str>,
) -> Result<bool, &'static str> {
    if draft.state == "created" && active_key == Some(draft.public_key.as_str()) {
        return Ok(true);
    }
    if draft.account != binding {
        return Err("device_draft_other_account");
    }
    if matches!(draft.state.as_str(), "submitted" | "unknown") {
        return Err("device_creation_outcome_unknown");
    }
    Ok(false)
}
#[cfg(any(windows, feature = "windows-api-check"))]
pub fn create(
    store: &adapter_platform::windows_store::PrivateStore,
    client: &MullvadClient,
    session: &AccountSession,
) -> Result<PublicDraft, &'static str> {
    let binding = session.binding_fingerprint();
    let active = crate::live_identity::load_identity(store).map_err(|e| e.code())?;
    let existing = if let Some(d) = load(store)? {
        if replace_completed(
            &d,
            &binding,
            active.as_ref().map(|v| v.metadata().public_key.as_str()),
        )? {
            store
                .archive(adapter_platform::storage_record::RecordKind::DeviceDraft)
                .map_err(|_| "device_draft_write_failed")?;
            None
        } else {
            if d.state == "created" {
                return Ok(public(&d));
            }
            Some(d)
        }
    } else {
        None
    };
    let mut d = if let Some(d) = existing {
        d
    } else {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *bytes).map_err(|_| "random_unavailable")?;
        let key = StaticSecret::from(*bytes);
        let d = Draft {
            schema: 1,
            account: binding,
            state: "prepared".into(),
            public_key: STANDARD.encode(PublicKey::from(&key).as_bytes()),
            private_key: Zeroizing::new(STANDARD.encode(&*bytes)),
            device_id: None,
            device_name: None,
            ipv4: None,
            ipv6: None,
        };
        save(store, &d)?;
        d
    };
    d.state = "submitted".into();
    save(store, &d)?;
    match client.create_device(session, &d.public_key) {
        Ok(created) => {
            d.device_id = Some(created.device.id.as_str().into());
            d.device_name = Some(created.device.name);
            d.ipv4 = Some(created.addresses.ipv4_address);
            d.ipv6 = Some(created.addresses.ipv6_address);
            d.state = "created".into();
            let _ = identity(&d)?;
            save(store, &d)?;
            Ok(public(&d))
        }
        Err(e) => {
            d.state = if e.requires_reconciliation() {
                "unknown"
            } else {
                "prepared"
            }
            .into();
            save(store, &d)?;
            Err(e.code())
        }
    }
}
#[cfg(any(windows, feature = "windows-api-check"))]
pub fn activate(
    store: &adapter_platform::windows_store::PrivateStore,
    client: &MullvadClient,
    session: &mut AccountSession,
) -> Result<TunnelIdentity, &'static str> {
    let d = load(store)?.ok_or("device_draft_missing")?;
    if d.account != session.binding_fingerprint() {
        return Err("device_draft_other_account");
    }
    let identity = identity(&d)?;
    let official = client
        .read_account(session, &d.public_key)
        .map_err(|e| e.code())?;
    if !official
        .devices
        .iter()
        .any(|v| v.current && Some(v.id.as_str()) == d.device_id.as_deref())
    {
        return Err("device_not_registered");
    }
    crate::live_identity::preserve_previous(store, &identity).map_err(|e| e.code())?;
    activation_commit(crate::live_identity::persist_identity(store, &identity))
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    struct Memory(RefCell<Option<Zeroizing<Vec<u8>>>>);
    impl Store for Memory {
        fn read(&self) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
            Ok(self.0.borrow().as_ref().map(|v| Zeroizing::new(v.to_vec())))
        }
        fn write(&self, v: &[u8]) -> io::Result<()> {
            *self.0.borrow_mut() = Some(Zeroizing::new(v.to_vec()));
            Ok(())
        }
    }
    fn draft() -> Draft {
        let key = StaticSecret::from([7u8; 32]);
        Draft {
            schema: 1,
            account: "a".repeat(64),
            state: "submitted".into(),
            public_key: STANDARD.encode(PublicKey::from(&key).as_bytes()),
            private_key: Zeroizing::new(STANDARD.encode(key.to_bytes())),
            device_id: None,
            device_name: None,
            ipv4: None,
            ipv6: None,
        }
    }
    #[test]
    fn only_activated_completed_drafts_allow_confirmed_replacement() {
        let mut d = draft();
        let same = d.account.clone();
        let other = "b".repeat(64);
        for state in ["prepared", "submitted", "unknown"] {
            d.state = state.into();
            assert_eq!(
                replace_completed(&d, &other, Some(&d.public_key)),
                Err("device_draft_other_account")
            );
        }
        for state in ["submitted", "unknown"] {
            d.state = state.into();
            assert_eq!(
                replace_completed(&d, &same, Some(&d.public_key)),
                Err("device_creation_outcome_unknown")
            );
        }
        d.state = "created".into();
        // A registration awaiting activation remains reusable, never a new POST.
        assert_eq!(replace_completed(&d, &same, None), Ok(false));
        assert_eq!(
            replace_completed(&d, &other, None),
            Err("device_draft_other_account")
        );
        assert_eq!(
            replace_completed(&d, &other, Some("different-key")),
            Err("device_draft_other_account")
        );
        assert_eq!(replace_completed(&d, &same, Some(&d.public_key)), Ok(true));
        assert_eq!(replace_completed(&d, &other, Some(&d.public_key)), Ok(true));
    }
    #[test]
    fn submitted_draft_survives_restart_without_claiming_registration() {
        let store = Memory(RefCell::new(None));
        save(&store, &draft()).unwrap();
        let restored = load(&store).unwrap().unwrap();
        assert_eq!(restored.state, "submitted");
        assert_eq!(public(&restored).device_id, None);
        assert_eq!(
            identity(&restored).err(),
            Some("device_creation_not_confirmed")
        );
    }
    #[test]
    fn corrupt_key_pair_and_future_schema_are_preserved_as_errors() {
        let store = Memory(RefCell::new(None));
        let mut d = draft();
        d.public_key = STANDARD.encode([3u8; 32]);
        store.write(&encode(&d).unwrap()).unwrap();
        assert_eq!(load(&store).err(), Some("device_draft_invalid"));
        let mut d = draft();
        d.schema = 2;
        store.write(&encode(&d).unwrap()).unwrap();
        assert_eq!(load(&store).err(), Some("device_draft_invalid"));
    }
}
