//! Current-user DPAPI primitive, not wired to account storage or mock IPC.
//! Callers own and must erase plaintext inputs. Decryption retains the OS buffer
//! without a plaintext Vec copy; it is wiped with volatile stores before LocalFree.
use std::{
    io,
    ptr::{null, null_mut},
    sync::atomic::{compiler_fence, Ordering},
};
use windows_sys::Win32::{Foundation::LocalFree, Security::Cryptography::*};
const MAX_SECRET: usize = 65536;
const MAX_ENVELOPE: usize = MAX_SECRET + 16384;
const PURPOSE: &[u8] = b"mullvad-adapter/windows/current-user-storage/v1";

pub struct Secret {
    pointer: *mut u8,
    len: usize,
}
impl Secret {
    pub fn expose(&self) -> &[u8] {
        if self.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.pointer, self.len) }
        }
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            for i in 0..self.len {
                unsafe {
                    std::ptr::write_volatile(self.pointer.add(i), 0);
                }
            }
        }
        compiler_fence(Ordering::SeqCst);
        unsafe {
            LocalFree(self.pointer.cast());
        }
    }
}
fn blob(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr().cast_mut(),
    }
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid protected secret")
}
pub fn protect(plaintext: &[u8]) -> io::Result<Vec<u8>> {
    if plaintext.is_empty() || plaintext.len() > MAX_SECRET {
        return Err(invalid());
    }
    let input = blob(plaintext);
    let entropy = blob(PURPOSE);
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    if unsafe {
        CryptProtectData(
            &input,
            null(),
            &entropy,
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let protected = Secret {
        pointer: output.pbData,
        len: output.cbData as usize,
    };
    if protected.len > MAX_ENVELOPE || protected.pointer.is_null() {
        return Err(invalid());
    }
    Ok(protected.expose().to_vec())
}
pub fn unprotect(envelope: &[u8]) -> io::Result<Secret> {
    unprotect_for_purpose(envelope, PURPOSE)
}
fn unprotect_for_purpose(envelope: &[u8], purpose: &[u8]) -> io::Result<Secret> {
    if envelope.is_empty() || envelope.len() > MAX_ENVELOPE {
        return Err(invalid());
    }
    let input = blob(envelope);
    let entropy = blob(purpose);
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    if unsafe {
        CryptUnprotectData(
            &input,
            null_mut(),
            &entropy,
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let secret = Secret {
        pointer: output.pbData,
        len: output.cbData as usize,
    };
    if secret.len == 0 || secret.len > MAX_SECRET || secret.pointer.is_null() {
        return Err(invalid());
    }
    Ok(secret)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current_user_roundtrip_and_tamper_rejection() {
        let plaintext = b"synthetic-test-value-not-an-account-key";
        let mut encrypted = protect(plaintext).unwrap();
        assert!(!encrypted.windows(plaintext.len()).any(|x| x == plaintext));
        assert_eq!(unprotect(&encrypted).unwrap().expose(), plaintext);
        let index = encrypted.len() / 2;
        encrypted[index] ^= 1;
        assert!(unprotect(&encrypted).is_err());
    }
    #[test]
    fn malformed_and_oversize_data_fail_closed() {
        assert!(protect(&[]).is_err());
        assert!(protect(&vec![0; MAX_SECRET + 1]).is_err());
        assert!(unprotect(&[]).is_err());
        assert!(unprotect(b"not-dpapi").is_err());
        assert!(unprotect(&vec![0; MAX_ENVELOPE + 1]).is_err());
    }
    #[test]
    fn exact_plaintext_limit_roundtrips_and_wrong_purpose_is_rejected() {
        let plaintext = vec![0x5a; MAX_SECRET];
        let encrypted = protect(&plaintext).unwrap();
        assert_eq!(unprotect(&encrypted).unwrap().expose(), plaintext);
        assert!(unprotect_for_purpose(&encrypted, b"different-purpose").is_err());
    }
}
