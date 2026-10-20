//! Last whole-tunnel success, stored separately from the next SS-only candidate.
//! The enclosing Windows record is DPAPI protected; never serialize this to IPC.
use adapter_engine_mihomo::chain::UpstreamSs;
use sha2::{Digest, Sha256};
use std::{io, sync::Arc};
use zeroize::Zeroizing;

pub(crate) struct VerifiedChain {
    pub(crate) proxy: Arc<UpstreamSs>,
    pub(crate) at: u64,
}
impl VerifiedChain {
    pub(crate) fn encode(&self) -> io::Result<Zeroizing<Vec<u8>>> {
        if self.at == 0 || self.at > 9_007_199_254_740_991 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let proxy = self.proxy.encode()?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(9 + proxy.len()));
        bytes.push(1);
        bytes.extend_from_slice(&self.at.to_le_bytes());
        bytes.extend_from_slice(&proxy);
        Ok(bytes)
    }
    pub(crate) fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() <= 9 || bytes[0] != 1 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let at = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
        if at == 0 || at > 9_007_199_254_740_991 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(Self {
            proxy: Arc::new(UpstreamSs::decode(&bytes[9..])?),
            at,
        })
    }
    pub(crate) fn matches(&self, fingerprint: Option<&str>) -> bool {
        self.proxy.encode().is_ok_and(|bytes| {
            fingerprint == Some(format!("{:x}", Sha256::digest(&bytes)).as_str())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn whole_route_snapshot_binds_credentials_and_version_without_ipc_plaintext() {
        let value = VerifiedChain {
            proxy: Arc::new(UpstreamSs::decode(br#"{"name":"synthetic","server":"ss.example.com","port":443,"cipher":"aes-128-gcm","password":"fixture-only"}"#).unwrap()),
            at: 42,
        };
        let bytes = value.encode().unwrap();
        let restored = VerifiedChain::decode(&bytes).unwrap();
        assert_eq!(restored.at, 42);
        let fingerprint = format!("{:x}", Sha256::digest(&*restored.proxy.encode().unwrap()));
        assert!(restored.matches(Some(&fingerprint)));
        assert!(!restored.matches(Some("different credentials")));
        assert!(!restored.matches(None));
        for n in 0..=9 {
            assert!(VerifiedChain::decode(&bytes[..n]).is_err());
        }
        let mut malformed = bytes.to_vec();
        malformed[0] = 2;
        assert!(VerifiedChain::decode(&malformed).is_err());
        malformed[0] = 1;
        malformed[1..9].fill(0);
        assert!(VerifiedChain::decode(&malformed).is_err());
        assert!(VerifiedChain::decode(&bytes[..bytes.len() - 1]).is_err());
    }
}
