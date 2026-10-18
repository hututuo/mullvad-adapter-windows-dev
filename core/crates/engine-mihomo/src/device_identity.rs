//! Derive peer exclusion from the actual key, never a caller supplied label.
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub(crate) fn fingerprint(private_key: &str) -> std::io::Result<[u8; 32]> {
    let invalid = || std::io::Error::other("invalid_device_key");
    let bytes = Zeroizing::new(STANDARD.decode(private_key).map_err(|_| invalid())?);
    let scalar: Zeroizing<[u8; 32]> =
        Zeroizing::new(bytes.as_slice().try_into().map_err(|_| invalid())?);
    let secret = StaticSecret::from(*scalar);
    let public = PublicKey::from(&secret);
    Ok(Sha256::digest(public.as_bytes()).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clamped_equivalent_keys_reserve_the_same_device() {
        let first = [0x11; 32];
        let mut equivalent = first;
        equivalent[0] ^= 7;
        equivalent[31] ^= 0xc0;
        assert_eq!(
            fingerprint(&STANDARD.encode(first)).unwrap(),
            fingerprint(&STANDARD.encode(equivalent)).unwrap()
        );
        assert_ne!(
            fingerprint(&STANDARD.encode(first)).unwrap(),
            fingerprint(&STANDARD.encode([0x22; 32])).unwrap()
        );
    }
    #[test]
    fn malformed_and_wrong_length_keys_cannot_create_a_peer_lease() {
        for key in [
            "not a key".into(),
            STANDARD.encode([1; 31]),
            STANDARD.encode([1; 33]),
        ] {
            assert!(fingerprint(&key).is_err());
        }
    }
}
