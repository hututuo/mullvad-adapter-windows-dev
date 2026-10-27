//! Official QUIC carrier inputs. Tokens never enter argv, logs or WG config.
use std::net::SocketAddr;
use zeroize::Zeroizing;
pub const OFFICIAL_UPSTREAM_SHA: &str = "19fb87407f4b81fe15372c2c7f8a20e7ab4eb220";

/// Owned only by the tunnel I/O operation; intentionally no Debug/Serialize.
pub struct Config {
    pub helper_executable: std::path::PathBuf,
    pub server_hostname: String,
    pub auth_token: Zeroizing<String>,
    pub target_endpoint: SocketAddr,
}

#[cfg(any(windows, feature = "windows-api-check"))]
pub(crate) mod windows {
    use super::*;
    use adapter_control::owned_lifecycle::BoundNetwork;
    use adapter_platform::{egress::EgressSnapshot, windows_process::HelperProcess};
    use std::{
        cell::RefCell,
        io,
        path::Path,
        time::{Duration, Instant},
    };
    pub struct Run {
        process: RefCell<HelperProcess>,
        local: SocketAddr,
        destination: std::net::IpAddr,
        remote: SocketAddr,
        binding: adapter_platform::physical_attachment::PhysicalBinding,
        witness: EgressSnapshot,
    }
    impl Run {
        pub fn open(
            directory: &Path,
            route: &EgressSnapshot,
            remote: SocketAddr,
            config: &Config,
            network: &BoundNetwork,
            deadline: Instant,
        ) -> io::Result<Self> {
            let executable = &config.helper_executable;
            if !executable.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "quic_helper_unavailable",
                ));
            }
            if config.server_hostname.len() > 253
                || config.server_hostname.is_empty()
                || config.auth_token.is_empty()
                || config.auth_token.len() > 4096
            {
                return Err(io::Error::other("quic_configuration_invalid"));
            }
            if config.target_endpoint != "127.0.0.1:51820".parse::<SocketAddr>().unwrap()
                || !route.is_fresh()
                || remote.ip() != route.destination()
                || remote.port() != 443
            {
                return Err(io::Error::other("quic_route_unavailable"));
            }
            let check = || {
                if network.is_cancelled() || Instant::now() >= deadline {
                    Err(io::Error::other("quic_start_cancelled"))
                } else {
                    Ok(())
                }
            };
            #[derive(serde::Serialize)]
            struct Request<'a> {
                schema: u8,
                remote_endpoint: SocketAddr,
                server_hostname: &'a str,
                auth_token: &'a str,
                target_endpoint: SocketAddr,
                interface_index: u32,
                interface_name: &'a str,
                source_address: std::net::IpAddr,
                mtu: u16,
            }
            let mut request = Zeroizing::new(Vec::with_capacity(8192));
            serde_json::to_writer(
                &mut *request,
                &Request {
                    schema: 1,
                    remote_endpoint: remote,
                    server_hostname: &config.server_hostname,
                    auth_token: &config.auth_token,
                    target_endpoint: config.target_endpoint,
                    interface_index: route.binding().index,
                    interface_name: route.alias(),
                    source_address: route.source(),
                    mtu: 1280,
                },
            )
            .map_err(|_| io::Error::other("quic_configuration_invalid"))?;
            let mut process = HelperProcess::spawn_checked(executable, directory, check)?;
            let ready = (|| {
                process.write_line(&request)?;
                loop {
                    check()?;
                    if let Some(line) = process.poll_line()? {
                        if remote_connect_failure(&line) {
                            return Err(io::Error::other("quic_connect_failed"));
                        }
                        return parse_ready(
                            &line,
                            route.binding().index,
                            route.alias(),
                            route.source(),
                            remote,
                        )
                        .ok_or_else(|| io::Error::other("quic_helper_protocol_invalid"));
                    }
                    if !process.is_running() {
                        return Err(io::Error::other("quic_helper_failed"));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            })();
            match ready {
                Ok(local) => {
                    let witness =
                        adapter_platform::egress::windows::snapshot(route.binding(), remote.ip());
                    let witness = match witness {
                        Ok(witness) if witness.is_fresh() && route.same_path(&witness) => witness,
                        _ => {
                            if process.stop_confirmed().is_err() {
                                return Err(io::Error::other("quic_cleanup_uncertain"));
                            }
                            return Err(io::Error::other("quic_route_unavailable"));
                        }
                    };
                    Ok(Self {
                        process: RefCell::new(process),
                        local,
                        destination: remote.ip(),
                        remote,
                        binding: route.binding(),
                        witness,
                    })
                }
                Err(mut error) => {
                    // A stale/changed physical route makes even a CONNECT error
                    // inconclusive locally. Never consume it as remote coverage.
                    if error.to_string() == "quic_connect_failed"
                        && (network.is_cancelled()
                            || !adapter_platform::egress::windows::snapshot(
                                route.binding(),
                                remote.ip(),
                            )
                            .is_ok_and(|fresh| fresh.is_fresh() && route.same_path(&fresh)))
                    {
                        error = io::Error::other("quic_route_unavailable");
                    }
                    if process.stop_confirmed().is_err() {
                        return Err(io::Error::other("quic_cleanup_uncertain"));
                    }
                    Err(error)
                }
            }
        }
        pub fn local(&self) -> SocketAddr {
            self.local
        }
        pub fn is_running(&self) -> bool {
            self.process.borrow().is_running()
        }
        /// Local ready has no data-plane meaning. The caller additionally checks
        /// real WG canaries and the same current physical route before promotion.
        pub fn current(&self, operation: &BoundNetwork) -> bool {
            !operation.is_cancelled()
                && operation.binding() == self.binding
                && self.is_running()
                && adapter_platform::egress::windows::snapshot(self.binding, self.destination)
                    .is_ok_and(|r| {
                        r.is_fresh()
                            && r.destination() == self.remote.ip()
                            && self.witness.same_path(&r)
                    })
        }
        pub fn stats(&self, operation: &BoundNetwork) -> io::Result<Stats> {
            let deadline = Instant::now() + Duration::from_secs(1);
            let mut process = self.process.borrow_mut();
            process.write_line(br#"{"action":"stats"}"#)?;
            loop {
                if operation.is_cancelled() || Instant::now() >= deadline || !process.is_running() {
                    return Err(io::Error::other("quic_stats_unavailable"));
                }
                if let Some(line) = process.poll_line()? {
                    return serde_json::from_slice::<Stats>(&line)
                        .ok()
                        .filter(|s| s.schema == 1 && s.event == "stats")
                        .ok_or_else(|| io::Error::other("quic_stats_invalid"));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        pub fn stop_confirmed(&mut self) -> io::Result<()> {
            self.process.borrow_mut().stop_confirmed()
        }
    }
}
#[cfg(any(windows, feature = "windows-api-check"))]
#[derive(serde::Deserialize)]
pub(crate) struct Stats {
    schema: u8,
    event: String,
    pub tx_packets: u64,
    pub rx_packets: u64,
}
fn remote_connect_failure(bytes: &[u8]) -> bool {
    if bytes.len() > 4096 {
        return false;
    }
    serde_json::from_slice::<serde_json::Value>(bytes).is_ok_and(|v| {
        v["schema"] == 1
            && v["event"] == "error"
            && matches!(
                v["code"].as_str(),
                Some("quic_connect_timeout" | "quic_connect_failed")
            )
    })
}
fn parse_ready(
    bytes: &[u8],
    interface_index: u32,
    interface_name: &str,
    source: std::net::IpAddr,
    remote: SocketAddr,
) -> Option<SocketAddr> {
    if bytes.len() > 4096 {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    if value["schema"] != 1
        || value["event"] != "ready"
        || value["transport"] != "quic"
        || value["carrier_authenticated"] != true
        || value["upstream_sha"] != OFFICIAL_UPSTREAM_SHA
    {
        return None;
    }
    let binding = &value["binding"];
    if binding["interface_index"].as_u64()? != u64::from(interface_index)
        || binding["interface_name"].as_str()? != interface_name
        || binding["remote_endpoint"]
            .as_str()?
            .parse::<SocketAddr>()
            .ok()?
            != remote
        || binding["source_address"]
            .as_str()?
            .parse::<std::net::IpAddr>()
            .ok()?
            != source
    {
        return None;
    }
    parse_loopback(value["local_endpoint"].as_str()?)
}
fn parse_loopback(text: &str) -> Option<SocketAddr> {
    let endpoint: SocketAddr = text.parse().ok()?;
    (endpoint.ip().is_loopback() && endpoint.port() != 0).then_some(endpoint)
}
#[cfg(test)]
mod tests {
    #[test]
    fn only_explicit_remote_connect_errors_consume_rotation() {
        for code in ["quic_connect_timeout", "quic_connect_failed"] {
            assert!(super::remote_connect_failure(
                serde_json::json!({"schema":1,"event":"error","code":code})
                    .to_string()
                    .as_bytes()
            ));
        }
        for code in [
            "physical_bind_failed",
            "quic_local_setup_failed",
            "local_bind_failed",
            "invalid_binding",
            "invalid_request",
            "parent_stopped_before_ready",
            "unknown",
        ] {
            assert!(!super::remote_connect_failure(
                serde_json::json!({"schema":1,"event":"error","code":code})
                    .to_string()
                    .as_bytes()
            ));
        }
    }
    #[test]
    fn ready_requires_authentication_and_exact_physical_receipt() {
        let mut value = serde_json::json!({"schema":1,"event":"ready","local_endpoint":"127.0.0.1:1234","transport":"quic","carrier_authenticated":true,"upstream_sha":super::OFFICIAL_UPSTREAM_SHA,"binding":{"interface_index":4,"interface_name":"Ethernet","source_address":"192.0.2.2","remote_endpoint":"192.0.2.1:443"}});
        let accepted = |v: &serde_json::Value| {
            super::parse_ready(
                v.to_string().as_bytes(),
                4,
                "Ethernet",
                "192.0.2.2".parse().unwrap(),
                "192.0.2.1:443".parse().unwrap(),
            )
            .is_some()
        };
        assert!(accepted(&value));
        value["carrier_authenticated"] = false.into();
        assert!(!accepted(&value));
        value["carrier_authenticated"] = true.into();
        for (field, wrong) in [
            ("interface_index", serde_json::json!(5)),
            ("interface_name", serde_json::json!("TUN")),
            ("source_address", serde_json::json!("192.0.2.3")),
            ("remote_endpoint", serde_json::json!("192.0.2.9:443")),
        ] {
            let mut bad = value.clone();
            bad["binding"][field] = wrong;
            assert!(!accepted(&bad));
        }
    }
    #[test]
    fn ready_accepts_only_bounded_loopback_protocol() {
        for endpoint in ["127.0.0.1:1234", "[::1]:1234"] {
            assert!(super::parse_loopback(endpoint).is_some());
        }
        for endpoint in ["192.0.2.1:1234", "127.0.0.1:0", "[::]:1234"] {
            assert!(super::parse_loopback(endpoint).is_none());
        }
    }
}
