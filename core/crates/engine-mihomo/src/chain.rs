//! A copied, independent SS leaf. Credentials stay in native RAM/DPAPI.
//! No external selector, generic SOCKS port or live WG peer is trusted here.
use serde::{Deserialize, Serialize};
use std::{io, net::Ipv4Addr};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    name: String,
    server: String,
    port: u16,
    cipher: String,
    #[serde(deserialize_with = "password", serialize_with = "write_password")]
    password: Zeroizing<String>,
}
fn password<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
fn write_password<S: serde::Serializer>(v: &Zeroizing<String>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(v)
}
pub struct UpstreamSs(Wire);
impl UpstreamSs {
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > 8192 {
            return Err(super::invalid());
        }
        let wire: Wire = serde_json::from_slice(bytes).map_err(|_| super::invalid())?;
        let value = Self(wire);
        if value.0.name.is_empty()
            || value.0.name.len() > MAX_NAME
            || value.0.name.chars().any(char::is_control)
            || value.0.password.is_empty()
            || value.0.password.len() > MAX_PASSWORD
            || value.0.password.chars().any(char::is_control)
            || value.0.port == 0
            || value.cipher().is_none()
            || !public_server(&value.0.server)
        {
            return Err(super::invalid());
        }
        Ok(value)
    }
    pub fn encode(&self) -> io::Result<Zeroizing<Vec<u8>>> {
        let mut writer = super::BoundedWriter(Zeroizing::new(Vec::with_capacity(16384)));
        serde_json::to_writer(&mut writer, &self.0).map_err(|_| super::invalid())?;
        Ok(writer.0)
    }
    pub fn name(&self) -> &str {
        &self.0.name
    }
    pub fn server(&self) -> &str {
        &self.0.server
    }
    pub fn port(&self) -> u16 {
        self.0.port
    }
    pub fn password(&self) -> &str {
        &self.0.password
    }
    pub fn cipher(&self) -> Option<&'static str> {
        match self.0.cipher.as_str() {
            "aes-128-gcm" => Some("aes-128-gcm"),
            "aes-256-gcm" => Some("aes-256-gcm"),
            "chacha20-ietf-poly1305" => Some("chacha20-ietf-poly1305"),
            _ => None,
        }
    }
}
pub use adapter_platform::chain_endpoint::public_ipv4;
use adapter_platform::chain_endpoint::{public_server, MAX_NAME, MAX_PASSWORD};

/// One bounded resolver lane per process. A stalled system resolver cannot
/// accumulate detached lookup threads or hold the connection owner's loop.
#[cfg(any(windows, feature = "windows-api-check"))]
pub(crate) fn resolve_ipv4(
    proxy: &UpstreamSs,
    network: &adapter_control::owned_lifecycle::BoundNetwork,
) -> io::Result<Ipv4Addr> {
    use std::{
        net::{IpAddr, ToSocketAddrs},
        sync::{mpsc, OnceLock},
        time::{Duration, Instant},
    };
    type Job = (String, u16, mpsc::SyncSender<Option<Ipv4Addr>>);
    static RESOLVER: OnceLock<Option<mpsc::SyncSender<Job>>> = OnceLock::new();
    if let Ok(ip) = proxy.server().parse::<Ipv4Addr>() {
        return if public_ipv4(ip) {
            Ok(ip)
        } else {
            Err(super::invalid())
        };
    }
    let sender = RESOLVER
        .get_or_init(|| {
            let (sender, jobs) = mpsc::sync_channel::<Job>(1);
            std::thread::Builder::new()
                .name("chain-system-resolver".into())
                .spawn(move || {
                    while let Ok((host, port, reply)) = jobs.recv() {
                        let address = (host.as_str(), port).to_socket_addrs().ok().and_then(
                            |mut addresses| {
                                addresses.find_map(|a| match a.ip() {
                                    IpAddr::V4(ip) if public_ipv4(ip) => Some(ip),
                                    _ => None,
                                })
                            },
                        );
                        let _ = reply.try_send(address);
                    }
                })
                .ok()
                .map(|_| sender)
        })
        .as_ref()
        .ok_or_else(super::invalid)?;
    let (reply, result) = mpsc::sync_channel(1);
    sender
        .try_send((proxy.server().into(), proxy.port(), reply))
        .map_err(|_| super::invalid())?;
    let deadline = Instant::now() + Duration::from_secs(4);
    while !network.is_cancelled() && Instant::now() < deadline {
        match result.recv_timeout(Duration::from_millis(20)) {
            Ok(Some(ip)) => return Ok(ip),
            Ok(None) | Err(mpsc::RecvTimeoutError::Disconnected) => return Err(super::invalid()),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
    Err(super::invalid())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_secret_roundtrip_and_validation() {
        let value = br#"{"name":"independent","server":"198.51.100.9","port":443,"cipher":"aes-128-gcm","password":"synthetic"}"#;
        let proxy = UpstreamSs::decode(value).unwrap();
        assert_eq!(proxy.name(), "independent");
        assert_eq!(
            UpstreamSs::decode(&proxy.encode().unwrap())
                .unwrap()
                .server(),
            "198.51.100.9"
        );
        for server in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.1.1",
            "198.18.0.1",
            "localhost",
            "adapter.local",
            "api.mullvad.net",
            "[::1]",
        ] {
            let bad = String::from_utf8(value.to_vec())
                .unwrap()
                .replace("198.51.100.9", server);
            assert!(UpstreamSs::decode(bad.as_bytes()).is_err(), "{server}");
        }
    }
}
