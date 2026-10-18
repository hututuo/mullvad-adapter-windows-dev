//! Versioned integrity envelope inside DPAPI. Validation is mandatory after a
//! successful decrypt; account/identity semantic validation is still the caller's job.
use sha2::{Digest, Sha256};
use std::io;
use zeroize::Zeroizing;
const MAGIC: &[u8; 8] = b"MADPST01";
const HEADER: usize = 48;
pub const MAX_PAYLOAD: usize = 65_536 - HEADER;
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum RecordKind {
    Account = 1,
    Identity = 2,
    Policy = 3,
    Connection = 4,
    DeviceDraft = 5,
    IdentityBackup = 6,
}
impl RecordKind {
    pub fn filename(self) -> &'static str {
        match self {
            Self::Account => "account.dpapi",
            Self::Identity => "identity.dpapi",
            Self::Policy => "policy.dpapi",
            Self::Connection => "connection.dpapi",
            Self::DeviceDraft => "device-draft.dpapi",
            Self::IdentityBackup => "identity-backup.dpapi",
        }
    }
}
// No Debug, Clone, Deref or Serialize: plaintext access must remain explicit.
pub struct PlainRecord(Zeroizing<Vec<u8>>);
impl PlainRecord {
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid stored record")
}
fn digest(prefix: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(prefix);
    hash.update(payload);
    hash.finalize().into()
}
pub fn encode(kind: RecordKind, payload: &[u8]) -> io::Result<PlainRecord> {
    if payload.is_empty() || payload.len() > MAX_PAYLOAD {
        return Err(invalid());
    }
    let mut out = Zeroizing::new(vec![0; HEADER + payload.len()]);
    out[..8].copy_from_slice(MAGIC);
    out[8] = 1;
    out[9] = kind as u8;
    out[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    out[HEADER..].copy_from_slice(payload);
    let hash = digest(&out[..16], &out[HEADER..]);
    out[16..HEADER].copy_from_slice(&hash);
    Ok(PlainRecord(out))
}
pub fn decode(kind: RecordKind, data: &[u8]) -> io::Result<&[u8]> {
    if data.len() <= HEADER
        || data.len() > HEADER + MAX_PAYLOAD
        || &data[..8] != MAGIC
        || data[8] != 1
        || data[9] != kind as u8
        || data[10..12] != [0, 0]
    {
        return Err(invalid());
    }
    let len = u32::from_le_bytes(data[12..16].try_into().map_err(|_| invalid())?) as usize;
    if len != data.len() - HEADER {
        return Err(invalid());
    }
    let hash = digest(&data[..16], &data[HEADER..]);
    if hash
        .iter()
        .zip(&data[16..HEADER])
        .fold(0u8, |a, (x, y)| a | (x ^ y))
        != 0
    {
        return Err(invalid());
    }
    Ok(&data[HEADER..])
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_and_every_single_byte_corruption_fails() {
        let value = encode(RecordKind::Identity, b"synthetic identity bytes").unwrap();
        assert_eq!(
            decode(RecordKind::Identity, value.expose()).unwrap(),
            b"synthetic identity bytes"
        );
        assert!(decode(RecordKind::Account, value.expose()).is_err());
        for index in 0..value.expose().len() {
            let mut corrupt = Zeroizing::new(value.expose().to_vec());
            corrupt[index] ^= 1;
            assert!(
                decode(RecordKind::Identity, &corrupt).is_err(),
                "accepted corruption at {index}"
            );
        }
    }
    #[test]
    fn length_version_and_maximum_are_explicit() {
        assert!(encode(RecordKind::Account, &[]).is_err());
        assert!(encode(RecordKind::Account, &vec![0; MAX_PAYLOAD + 1]).is_err());
        let max = encode(RecordKind::Account, &vec![0x5a; MAX_PAYLOAD]).unwrap();
        assert_eq!(max.expose().len(), 65536);
        assert_eq!(
            decode(RecordKind::Account, max.expose()).unwrap().len(),
            MAX_PAYLOAD
        );
        assert!(decode(RecordKind::Account, &max.expose()[..HEADER]).is_err());
        let mut extra = Zeroizing::new(max.expose().to_vec());
        extra.push(0);
        assert!(decode(RecordKind::Account, &extra).is_err());
    }
    #[test]
    fn malformed_headers_fail_even_with_a_recomputed_checksum() {
        let record = encode(RecordKind::Identity, b"synthetic").unwrap();
        for offset in [0, 8, 9, 10, 11, 12] {
            let mut malformed = Zeroizing::new(record.expose().to_vec());
            malformed[offset] ^= 1;
            let hash = digest(&malformed[..16], &malformed[HEADER..]);
            malformed[16..HEADER].copy_from_slice(&hash);
            assert!(
                decode(RecordKind::Identity, &malformed).is_err(),
                "accepted malformed header at {offset}"
            );
        }
        for kind in [
            RecordKind::Account,
            RecordKind::Identity,
            RecordKind::Policy,
            RecordKind::Connection,
            RecordKind::DeviceDraft,
            RecordKind::IdentityBackup,
        ] {
            let valid = encode(kind, b"value").unwrap();
            let borrowed = decode(kind, valid.expose()).unwrap();
            assert_eq!(borrowed.as_ptr(), valid.expose()[HEADER..].as_ptr());
        }
    }
}
