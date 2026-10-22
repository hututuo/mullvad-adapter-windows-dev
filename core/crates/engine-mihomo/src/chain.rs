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

/// Isolate potentially uninterruptible system DNS from the bounded Clash lane.
/// There are at most two fixed threads and two one-job queues in this process;
/// a stuck system call cannot prevent a later successful Clash DNS query.
#[cfg(any(windows, feature = "windows-api-check", test))]
struct SystemLookup(std::sync::mpsc::SyncSender<SystemJob>);
#[cfg(any(windows, feature = "windows-api-check", test))]
type SystemJob = (
    String,
    u16,
    std::time::Instant,
    std::sync::mpsc::SyncSender<Option<Ipv4Addr>>,
);
#[cfg(any(windows, feature = "windows-api-check", test))]
impl SystemLookup {
    fn start(lookup: impl Fn(&str, u16) -> Option<Ipv4Addr> + Send + 'static) -> io::Result<Self> {
        let (send, receive) = std::sync::mpsc::sync_channel::<SystemJob>(1);
        std::thread::Builder::new()
            .name("chain-system-resolver".into())
            .spawn(move || {
                while let Ok((host, port, deadline, reply)) = receive.recv() {
                    if std::time::Instant::now() < deadline {
                        let result = lookup(&host, port);
                        let _ = reply.try_send(result);
                    }
                }
            })?;
        Ok(Self(send))
    }
    fn resolve(&self, host: String, port: u16, deadline: std::time::Instant) -> Option<Ipv4Addr> {
        let deadline = lookup_deadline(deadline, std::time::Instant::now())?;
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        self.0.try_send((host, port, deadline, send)).ok()?;
        receive
            .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            .ok()
            .flatten()
            .filter(|_| std::time::Instant::now() < deadline)
    }
}

#[cfg(any(windows, feature = "windows-api-check", test))]
fn lookup_deadline(
    parent: std::time::Instant,
    now: std::time::Instant,
) -> Option<std::time::Instant> {
    (parent > now).then(|| parent.min(now + std::time::Duration::from_secs(4)))
}

/// One bounded primary lane per process; the state owner never waits on DNS.
#[cfg(any(windows, feature = "windows-api-check"))]
pub(crate) fn resolve_ipv4(
    proxy: &UpstreamSs,
    network: &adapter_control::owned_lifecycle::BoundNetwork,
    parent_deadline: std::time::Instant,
) -> io::Result<Ipv4Addr> {
    use std::{
        net::{IpAddr, ToSocketAddrs},
        sync::{mpsc, OnceLock},
        time::{Duration, Instant},
    };
    type Job = (String, u16, Instant, mpsc::SyncSender<Option<Ipv4Addr>>);
    static RESOLVER: OnceLock<Option<mpsc::SyncSender<Job>>> = OnceLock::new();
    static SYSTEM: OnceLock<Option<SystemLookup>> = OnceLock::new();
    let deadline = lookup_deadline(parent_deadline, Instant::now()).ok_or_else(super::invalid)?;
    if network.is_cancelled() {
        return Err(super::invalid());
    }
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
                .name("chain-dns-bootstrap".into())
                .spawn(move || {
                    while let Ok((host, port, deadline, reply)) = jobs.recv() {
                        if Instant::now() >= deadline {
                            let _ = reply.try_send(None);
                            continue;
                        }
                        // Clash fake-IP is not a physical endpoint. Ask its
                        // credential-free local DNS control API for real A data
                        // before system resolution; retain the hostname and
                        // repeat this lookup for every new worker.
                        let address = adapter_clash_integration::chain_dns::current_windows_ipv4(
                            &host,
                            deadline
                                .saturating_duration_since(Instant::now())
                                .min(Duration::from_secs(2)),
                        )
                        .ok()
                        .or_else(|| {
                            if Instant::now() >= deadline {
                                return None;
                            }
                            SYSTEM
                                .get_or_init(|| {
                                    SystemLookup::start(|host, port| {
                                        (host, port).to_socket_addrs().ok()?.find_map(|a| {
                                            match a.ip() {
                                                IpAddr::V4(ip) if public_ipv4(ip) => Some(ip),
                                                _ => None,
                                            }
                                        })
                                    })
                                    .ok()
                                })
                                .as_ref()?
                                .resolve(host.clone(), port, deadline)
                        });
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
        .try_send((proxy.server().into(), proxy.port(), deadline, reply))
        .map_err(|_| super::invalid())?;
    while !network.is_cancelled() && Instant::now() < deadline {
        match result.recv_timeout(
            Duration::from_millis(20).min(deadline.saturating_duration_since(Instant::now())),
        ) {
            Ok(Some(ip)) if Instant::now() < deadline && !network.is_cancelled() => return Ok(ip),
            Ok(Some(_)) => return Err(super::invalid()),
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
    fn resolver_budget_keeps_parent_deadline_and_refuses_expired_work() {
        use std::time::{Duration, Instant};
        let now = Instant::now();
        assert_eq!(lookup_deadline(now, now), None);
        assert_eq!(lookup_deadline(now - Duration::from_millis(1), now), None);
        assert_eq!(
            lookup_deadline(now + Duration::from_millis(40), now),
            Some(now + Duration::from_millis(40))
        );
        assert_eq!(
            lookup_deadline(now + Duration::from_secs(15), now),
            Some(now + Duration::from_secs(4))
        );
    }
    #[test]
    fn expired_lookup_never_enters_system_lane() {
        use std::time::Instant;
        let lane =
            SystemLookup::start(|_, _| panic!("expired work must never reach native resolver"))
                .unwrap();
        assert!(lane
            .resolve("node.example".into(), 443, Instant::now())
            .is_none());
    }
    #[test]
    fn stalled_system_dns_has_a_deadline_and_bounded_queue() {
        use std::{
            sync::mpsc,
            time::{Duration, Instant},
        };
        let (entered, started) = mpsc::sync_channel(1);
        let (release, blocked) = mpsc::sync_channel(1);
        let blocked = std::sync::Mutex::new(blocked);
        let lane = SystemLookup::start(move |_, _| {
            let _ = entered.try_send(());
            blocked
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
            Some(Ipv4Addr::new(203, 0, 113, 7))
        })
        .unwrap();
        let start = Instant::now();
        assert!(lane
            .resolve(
                "node.example".into(),
                443,
                start + Duration::from_millis(25)
            )
            .is_none());
        started.recv_timeout(Duration::from_secs(1)).unwrap();
        // A caller can return, including when one queued job is also waiting.
        assert!(lane
            .resolve(
                "node.example".into(),
                443,
                Instant::now() + Duration::from_millis(25)
            )
            .is_none());
        assert!(lane
            .resolve(
                "node.example".into(),
                443,
                Instant::now() + Duration::from_millis(25)
            )
            .is_none());
        assert!(start.elapsed() < Duration::from_secs(1));
        release.send(()).unwrap();
    }
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
