//! Pure Mihomo configuration contracts. No process, file, socket or live peer use.
mod carrier;
#[cfg(any(test, windows, feature = "windows-api-check"))]
mod device_identity;
#[cfg(any(test, windows, feature = "windows-api-check"))]
mod promotion_gate;
use serde::Serialize;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use zeroize::Zeroizing;

pub const ENGINE_COMPATIBILITY_TARGET: &str = "mihomo-v1.19.31";
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    Standard,
    MultihopRequired,
    PostQuantumRequired,
}
#[derive(Clone, Copy)]
pub enum Transport {
    DirectV4 { endpoint: Ipv4Addr, port: u16 },
    DirectV6 { endpoint: Ipv6Addr, port: u16 },
    Shadowsocks { endpoint: Ipv4Addr, port: u16 },
}
/// Caller owns the original secrets and their lifetime; this view does not copy them.
pub struct Identity<'a> {
    pub private_key: &'a str,
    pub preshared_key: Option<&'a str>,
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
}
/// This is a configuration input, not verified OS binding evidence. Before launch,
/// the owner must revalidate alias/LUID/index/family and actual endpoint egress.
pub struct Egress<'a> {
    pub alias: &'a str,
    pub luid: u64,
    pub index: u32,
    pub ipv4: bool,
    pub ipv6: bool,
}
pub struct Listener<'a> {
    pub mixed_port: u16,
    pub controller_port: u16,
    pub controller_secret: &'a str,
}
pub struct WorkerInput<'a> {
    pub identity: Identity<'a>,
    pub relay_public_key: &'a str,
    pub transport: Transport,
    pub protection: Protection,
    pub egress: Egress<'a>,
    pub listener: Listener<'a>,
}
/// Contains plaintext credentials. No Debug/Clone/Serialize. Explicit borrowing
/// only; the caller must use a private ephemeral file and never ordinary logs.
pub struct SecretConfig(Zeroizing<Vec<u8>>);
impl SecretConfig {
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid or unsupported engine configuration",
    )
}
fn key32(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 44 || bytes[43] != b'=' {
        return false;
    }
    fn digit(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    bytes[..43].iter().all(|b| digit(*b).is_some())
        && digit(bytes[42]).is_some_and(|x| x & 3 == 0)
        && bytes[..43].iter().any(|b| *b != b'A')
}
fn endpoint_valid(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_private()
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_unicast_link_local()
                && !ip.is_multicast()
                && !ip.is_unique_local()
                && ip.to_ipv4_mapped().is_none()
        }
    }
}
fn listener_valid(input: &Listener<'_>) -> bool {
    input.mixed_port >= 1024
        && input.controller_port >= 1024
        && input.mixed_port != input.controller_port
        && input.controller_secret.len() == 64
        && input
            .controller_secret
            .bytes()
            .all(|c| c.is_ascii_hexdigit())
}
#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Config<'a> {
    mixed_port: u16,
    bind_address: &'static str,
    external_controller: String,
    secret: &'a str,
    allow_lan: bool,
    mode: &'static str,
    log_level: &'static str,
    ipv6: bool,
    tun: Enabled,
    ntp: Enabled,
    sniffer: Enabled,
    geo_auto_update: bool,
    profile: Profile,
    external_controller_cors: Cors,
    dns: Enabled,
    proxies: Vec<Proxy<'a>>,
    proxy_groups: Vec<Group>,
    rules: [&'static str; 1],
}
#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Profile {
    store_selected: bool,
    store_fake_ip: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Cors {
    allow_origins: [&'static str; 1],
    allow_private_network: bool,
}
#[derive(Serialize)]
struct Enabled {
    enable: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Proxy<'a> {
    name: &'static str,
    #[serde(rename = "type")]
    kind: &'static str,
    server: String,
    port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "pre-shared-key")]
    preshared_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv6: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_version: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dialer_proxy: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cipher: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtu: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    persistent_keepalive: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_dns_resolve: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns: Option<[&'static str; 1]>,
    udp: bool,
}
impl Proxy<'_> {
    fn empty(name: &'static str, kind: &'static str, server: String, port: u16) -> Self {
        Self {
            name,
            kind,
            server,
            port,
            private_key: None,
            preshared_key: None,
            public_key: None,
            ip: None,
            ipv6: None,
            interface_name: None,
            ip_version: None,
            dialer_proxy: None,
            cipher: None,
            password: None,
            username: None,
            mtu: None,
            persistent_keepalive: None,
            remote_dns_resolve: None,
            dns: None,
            udp: true,
        }
    }
}
#[derive(Serialize)]
struct Group {
    name: &'static str,
    #[serde(rename = "type")]
    kind: &'static str,
    proxies: Vec<&'static str>,
}
fn config<'a>(
    listener: &Listener<'a>,
    ipv6: bool,
    proxies: Vec<Proxy<'a>>,
    choices: Vec<&'static str>,
) -> Config<'a> {
    Config {
        mixed_port: listener.mixed_port,
        bind_address: "127.0.0.1",
        external_controller: format!("127.0.0.1:{}", listener.controller_port),
        secret: listener.controller_secret,
        allow_lan: false,
        mode: "rule",
        log_level: "warning",
        ipv6,
        tun: Enabled { enable: false },
        ntp: Enabled { enable: false },
        sniffer: Enabled { enable: false },
        geo_auto_update: false,
        profile: Profile {
            store_selected: false,
            store_fake_ip: false,
        },
        external_controller_cors: Cors {
            // chi v0.1.1 treats an empty list as wildcard. A nonempty list
            // containing only the empty string matches no browser Origin.
            allow_origins: [""],
            allow_private_network: false,
        },
        dns: Enabled { enable: false },
        proxies,
        proxy_groups: vec![Group {
            name: "OUT",
            kind: "select",
            proxies: choices,
        }],
        rules: ["MATCH,OUT"],
    }
}
struct BoundedWriter(Zeroizing<Vec<u8>>);
impl io::Write for BoundedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > 16384 - self.0.len() {
            return Err(invalid());
        }
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode(value: &Config<'_>) -> io::Result<SecretConfig> {
    // Fixed capacity and bounded writes prevent reallocation from abandoning
    // previously serialized plaintext in a released allocation.
    let mut writer = BoundedWriter(Zeroizing::new(Vec::with_capacity(16384)));
    serde_json::to_writer(&mut writer, value).map_err(|_| invalid())?;
    Ok(SecretConfig(writer.0))
}

/// Require a fresh, interface-constrained route snapshot for the exact endpoint.
/// This validates configuration inputs; it is not proof of packets sent by Mihomo.
pub fn worker_with_route(
    input: &WorkerInput<'_>,
    route: &adapter_platform::egress::EgressSnapshot,
) -> io::Result<SecretConfig> {
    worker_bound_config(input, route, false)
}
/// Explicit maintenance-only verbose output; the parent accepts closed labels,
/// never raw log lines. Routing and all secret-input validation stay identical.
pub fn worker_with_route_diagnostic(
    input: &WorkerInput<'_>,
    route: &adapter_platform::egress::EgressSnapshot,
) -> io::Result<SecretConfig> {
    worker_bound_config(input, route, true)
}
fn worker_bound_config(
    input: &WorkerInput<'_>,
    route: &adapter_platform::egress::EgressSnapshot,
    diagnostic: bool,
) -> io::Result<SecretConfig> {
    if !route.is_fresh()
        || !route_matches(input, route.binding(), route.alias(), route.destination())
    {
        return Err(invalid());
    }
    let config = worker_config_with_output(input, None, diagnostic)?;
    if !route.is_fresh() {
        return Err(invalid());
    }
    Ok(config)
}

fn route_matches(
    input: &WorkerInput<'_>,
    binding: adapter_platform::physical_attachment::PhysicalBinding,
    alias: &str,
    destination: IpAddr,
) -> bool {
    let endpoint = match input.transport {
        Transport::DirectV4 { endpoint, .. } | Transport::Shadowsocks { endpoint, .. } => {
            IpAddr::V4(endpoint)
        }
        Transport::DirectV6 { endpoint, .. } => IpAddr::V6(endpoint),
    };
    destination == endpoint
        && input.egress.alias == alias
        && input.egress.luid == binding.luid
        && input.egress.index == binding.index
        && (if endpoint.is_ipv4() {
            binding.ipv4
        } else {
            binding.ipv6
        })
}

pub fn worker(input: &WorkerInput<'_>) -> io::Result<SecretConfig> {
    worker_config(input, None)
}

/// A fixed loopback carrier capability, borrowed only into private config stdin.
/// It is never an OUT choice. The caller must start and retain the authenticated
/// carrier and separately verify its actual physical socket; YAML is not proof.
pub struct Carrier<'a> {
    pub port: u16,
    pub password: &'a str,
}
pub fn worker_with_carrier_route(
    input: &WorkerInput<'_>,
    route: &adapter_platform::egress::EgressSnapshot,
    carrier: &Carrier<'_>,
) -> io::Result<SecretConfig> {
    if !route.is_fresh()
        || !route_matches(input, route.binding(), route.alias(), route.destination())
    {
        return Err(invalid());
    }
    let config = worker_config(input, Some(carrier))?;
    if !route.is_fresh() {
        return Err(invalid());
    }
    Ok(config)
}
fn worker_config(
    input: &WorkerInput<'_>,
    carrier: Option<&Carrier<'_>>,
) -> io::Result<SecretConfig> {
    worker_config_with_output(input, carrier, false)
}
fn worker_config_with_output(
    input: &WorkerInput<'_>,
    carrier: Option<&Carrier<'_>>,
    diagnostic: bool,
) -> io::Result<SecretConfig> {
    if carrier.is_some_and(|carrier| {
        carrier.port < 1024
            || carrier.port == input.listener.mixed_port
            || carrier.port == input.listener.controller_port
            || carrier.password.len() != 64
            || !carrier.password.bytes().all(|b| b.is_ascii_hexdigit())
    }) {
        return Err(invalid());
    }
    if input.protection != Protection::Standard
        || !key32(input.identity.private_key)
        || !key32(input.relay_public_key)
        || input.identity.preshared_key.is_some_and(|key| !key32(key))
        || !listener_valid(&input.listener)
        || input.egress.luid == 0
        || input.egress.index == 0
        || input.egress.alias.is_empty()
        || input.egress.alias.encode_utf16().count() > 256
        || input.egress.alias.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    if input.identity.ipv4.is_unspecified()
        || input.identity.ipv4.is_loopback()
        || input.identity.ipv4.is_link_local()
        || input.identity.ipv4.is_multicast()
        || input.identity.ipv4.is_broadcast()
    {
        return Err(invalid());
    }
    if input.identity.ipv6.is_some_and(|ip| {
        ip.is_unspecified()
            || ip.is_loopback()
            || ip.is_unicast_link_local()
            || ip.is_multicast()
            || ip.to_ipv4_mapped().is_some()
    }) {
        return Err(invalid());
    }
    let (endpoint, port, v6) = match input.transport {
        Transport::DirectV4 { endpoint, port } => (IpAddr::V4(endpoint), port, false),
        Transport::DirectV6 { endpoint, port } => (IpAddr::V6(endpoint), port, true),
        Transport::Shadowsocks { endpoint, port } => (IpAddr::V4(endpoint), port, false),
    };
    if !endpoint_valid(endpoint)
        || port == 0
        || (v6 && !input.egress.ipv6)
        || (!v6 && !input.egress.ipv4)
    {
        return Err(invalid());
    }
    let mut wg = Proxy::empty("MULLVAD", "wireguard", endpoint.to_string(), port);
    wg.private_key = Some(input.identity.private_key);
    wg.preshared_key = input.identity.preshared_key;
    wg.public_key = Some(input.relay_public_key);
    wg.ip = Some(input.identity.ipv4.to_string());
    wg.ipv6 = input.identity.ipv6.map(|ip| ip.to_string());
    // Preserve the outbound NAT mapping during idle periods. This does not
    // bypass blocked UDP and is not a substitute for measured readiness.
    wg.persistent_keepalive = Some(25);
    wg.remote_dns_resolve = Some(true);
    wg.dns = Some(["tcp://10.64.0.1"]);
    wg.mtu = Some(1280);
    let mut proxies = vec![];
    match input.transport {
        Transport::DirectV4 { .. } => {
            wg.interface_name = Some(input.egress.alias);
            wg.ip_version = Some("ipv4");
        }
        Transport::DirectV6 { .. } => {
            wg.interface_name = Some(input.egress.alias);
        } // no WG ip-version=ipv6: affects inner IPv4
        Transport::Shadowsocks { .. } => {
            let mut ss = Proxy::empty("SS-INLET", "ss", endpoint.to_string(), port);
            ss.cipher = Some("aes-256-gcm");
            ss.password = Some("mullvad");
            ss.interface_name = if carrier.is_none() {
                Some(input.egress.alias)
            } else {
                None
            };
            ss.dialer_proxy = carrier.map(|_| "CARRIER");
            ss.ip_version = Some("ipv4");
            proxies.push(ss);
            wg.server = "127.0.0.1".into();
            wg.port = 51820;
            wg.dialer_proxy = Some("SS-INLET");
            wg.mtu = Some(1265);
        }
    }
    if let Some(carrier) = carrier {
        // The engine now reaches a loopback SOCKS endpoint. Physical binding is
        // performed by the owned carrier; binding this loopback dial to the WAN
        // interface would break it or bypass the intended proof boundary.
        wg.interface_name = None;
        if !matches!(input.transport, Transport::Shadowsocks { .. }) {
            wg.dialer_proxy = Some("CARRIER");
        }
        let mut inlet = Proxy::empty("CARRIER", "socks5", "127.0.0.1".into(), carrier.port);
        inlet.username = Some("adapter");
        inlet.password = Some(carrier.password);
        inlet.ip_version = Some("ipv4");
        proxies.push(inlet);
    }
    proxies.push(wg);
    let mut output = config(&input.listener, v6, proxies, vec!["MULLVAD"]);
    if diagnostic {
        output.log_level = "debug";
    }
    encode(&output)
}
/// Front starts rejecting traffic; only the transaction owner may select a ready
/// slot later. It never includes DIRECT as a selectable fallback.
pub fn front(listener: &Listener<'_>, slot_a: u16, slot_b: u16) -> io::Result<SecretConfig> {
    if !listener_valid(listener)
        || slot_a < 1024
        || slot_b < 1024
        || slot_a == slot_b
        || [slot_a, slot_b]
            .iter()
            .any(|p| *p == listener.mixed_port || *p == listener.controller_port)
    {
        return Err(invalid());
    }
    let proxies = vec![
        Proxy::empty("SLOT-A", "socks5", "127.0.0.1".into(), slot_a),
        Proxy::empty("SLOT-B", "socks5", "127.0.0.1".into(), slot_b),
    ];
    encode(&config(
        listener,
        true,
        proxies,
        vec!["REJECT", "SLOT-A", "SLOT-B"],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    #[test]
    fn carrier_is_only_an_authenticated_loopback_dialer_and_never_an_out_choice() {
        for transport in [
            Transport::DirectV4 {
                endpoint: "192.0.2.1".parse().unwrap(),
                port: 51820,
            },
            Transport::DirectV6 {
                endpoint: "2001:db8::1".parse().unwrap(),
                port: 51820,
            },
            Transport::Shadowsocks {
                endpoint: "192.0.2.1".parse().unwrap(),
                port: 51900,
            },
        ] {
            let input = input(transport);
            let config = worker_config(
                &input,
                Some(&Carrier {
                    port: 15000,
                    password: SECRET,
                }),
            )
            .unwrap();
            let json: serde_json::Value = serde_json::from_slice(config.expose()).unwrap();
            assert_eq!(
                json["proxy-groups"][0]["proxies"],
                serde_json::json!(["MULLVAD"])
            );
            let proxies = json["proxies"].as_array().unwrap();
            assert_eq!(
                proxies.iter().find(|p| p["name"] == "MULLVAD").unwrap()["persistent-keepalive"],
                25
            );
            assert!(proxies.iter().all(|p| p.get("interface-name").is_none()));
            let carrier = proxies.iter().find(|p| p["name"] == "CARRIER").unwrap();
            assert_eq!(carrier["server"], "127.0.0.1");
            assert_eq!(carrier["username"], "adapter");
            assert_eq!(carrier["password"], SECRET);
            let wg = proxies.iter().find(|p| p["name"] == "MULLVAD").unwrap();
            if matches!(transport, Transport::Shadowsocks { .. }) {
                assert_eq!(wg["dialer-proxy"], "SS-INLET");
                assert_eq!(wg["server"], "127.0.0.1");
                assert_eq!(
                    proxies.iter().find(|p| p["name"] == "SS-INLET").unwrap()["dialer-proxy"],
                    "CARRIER"
                );
            } else {
                assert_eq!(wg["dialer-proxy"], "CARRIER");
            }
            assert!(worker_config(
                &input,
                Some(&Carrier {
                    port: input.listener.mixed_port,
                    password: SECRET
                })
            )
            .is_err());
            assert!(worker_config(
                &input,
                Some(&Carrier {
                    port: 15000,
                    password: "short"
                })
            )
            .is_err());
        }
    }
    fn input(transport: Transport) -> WorkerInput<'static> {
        WorkerInput {
            identity: Identity {
                private_key: KEY,
                preshared_key: None,
                ipv4: "10.64.0.2".parse().unwrap(),
                ipv6: Some("fc00::2".parse().unwrap()),
            },
            relay_public_key: KEY,
            transport,
            protection: Protection::Standard,
            egress: Egress {
                alias: "Ethernet fixture",
                luid: 7,
                index: 4,
                ipv4: true,
                ipv6: true,
            },
            listener: Listener {
                mixed_port: 51001,
                controller_port: 51002,
                controller_secret: SECRET,
            },
        }
    }
    fn v4() -> Transport {
        Transport::DirectV4 {
            endpoint: "192.0.2.1".parse().unwrap(),
            port: 51820,
        }
    }
    fn parsed(bytes: SecretConfig) -> serde_json::Value {
        serde_json::from_slice(bytes.expose()).unwrap()
    }
    #[test]
    fn key_format_is_strict_and_canonical_without_copying_plaintext() {
        assert!(key32(KEY));
        assert!(!key32("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        assert!(!key32("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEC="));
        assert!(!key32(&format!("{KEY}\n")));
        assert!(!key32(&KEY[..43]));
    }
    #[test]
    fn direct_ipv4_is_loopback_only_and_explicitly_bound() {
        let value = parsed(worker(&input(v4())).unwrap());
        let wg = &value["proxies"][0];
        assert_eq!(value["bind-address"], "127.0.0.1");
        assert_eq!(value["allow-lan"], false);
        assert_eq!(value["external-controller"], "127.0.0.1:51002");
        assert_eq!(value["secret"], SECRET);
        for key in ["tun", "dns", "ntp", "sniffer"] {
            assert_eq!(value[key]["enable"], false);
        }
        assert_eq!(value["profile"]["store-selected"], false);
        assert_eq!(value["geo-auto-update"], false);
        assert_eq!(
            value["external-controller-cors"]["allow-origins"],
            serde_json::json!([""])
        );
        assert_eq!(wg["interface-name"], "Ethernet fixture");
        assert_eq!(wg["ip-version"], "ipv4");
        assert_eq!(wg["server"], "192.0.2.1");
        assert!(wg.get("dialer-proxy").is_none());
        assert_eq!(wg["dns"][0], "tcp://10.64.0.1");
        assert_eq!(value["rules"][0], "MATCH,OUT");
    }
    #[test]
    fn direct_ipv6_does_not_force_inner_ipv6() {
        let value = parsed(
            worker(&input(Transport::DirectV6 {
                endpoint: "2001:db8::1".parse().unwrap(),
                port: 33431,
            }))
            .unwrap(),
        );
        let wg = &value["proxies"][0];
        assert_eq!(value["ipv6"], true);
        assert_eq!(wg["server"], "2001:db8::1");
        assert!(wg.get("ip-version").is_none());
        assert_eq!(wg["interface-name"], "Ethernet fixture");
    }
    #[test]
    fn shadowsocks_binds_only_outer_inlet_and_keeps_inner_target() {
        let value = parsed(
            worker(&input(Transport::Shadowsocks {
                endpoint: "198.51.100.2".parse().unwrap(),
                port: 443,
            }))
            .unwrap(),
        );
        let ss = &value["proxies"][0];
        let wg = &value["proxies"][1];
        assert_eq!(ss["name"], "SS-INLET");
        assert_eq!(ss["interface-name"], "Ethernet fixture");
        assert_eq!(ss["cipher"], "aes-256-gcm");
        assert_eq!(ss["password"], "mullvad");
        assert_eq!(wg["server"], "127.0.0.1");
        assert_eq!(wg["port"], 51820);
        assert_eq!(wg["dialer-proxy"], "SS-INLET");
        assert_eq!(wg["mtu"], 1265);
        assert!(wg.get("interface-name").is_none());
        assert!(wg.get("ip-version").is_none());
    }
    #[test]
    fn static_preshared_key_is_preserved_but_never_counts_as_pq() {
        let mut request = input(v4());
        request.identity.preshared_key = Some(KEY);
        assert_eq!(
            parsed(worker(&request).unwrap())["proxies"][0]["pre-shared-key"],
            KEY
        );
        request.protection = Protection::PostQuantumRequired;
        assert!(worker(&request).is_err());
        request.protection = Protection::Standard;
        request.identity.preshared_key = Some("invalid");
        assert!(worker(&request).is_err());
    }
    #[test]
    fn required_protection_never_silently_downgrades() {
        for profile in [
            Protection::MultihopRequired,
            Protection::PostQuantumRequired,
        ] {
            let mut request = input(v4());
            request.protection = profile;
            assert!(worker(&request).is_err());
        }
    }
    #[test]
    fn invalid_family_or_local_endpoint_is_rejected() {
        let mut request = input(v4());
        request.egress.ipv4 = false;
        assert!(worker(&request).is_err());
        for endpoint in [
            "0.0.0.0",
            "127.0.0.1",
            "169.254.1.1",
            "192.168.1.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(worker(&input(Transport::DirectV4 {
                endpoint: endpoint.parse().unwrap(),
                port: 51820
            }))
            .is_err());
        }
        for endpoint in [
            "::",
            "::1",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "::ffff:192.0.2.1",
        ] {
            assert!(worker(&input(Transport::DirectV6 {
                endpoint: endpoint.parse().unwrap(),
                port: 51820
            }))
            .is_err());
        }
    }
    #[test]
    fn listener_alias_key_and_port_rejections_are_not_secret_echoes() {
        let mut request = input(v4());
        request.listener.controller_secret = "not-a-valid-secret";
        let err = worker(&request).err().unwrap();
        assert_eq!(
            err.to_string(),
            "invalid or unsupported engine configuration"
        );
        request = input(v4());
        request.listener.controller_port = request.listener.mixed_port;
        assert!(worker(&request).is_err());
        request = input(v4());
        request.egress.alias = "Ethernet\nsecret";
        assert!(worker(&request).is_err());
        request = input(v4());
        request.identity.private_key = "bad key";
        assert!(worker(&request).is_err());
        request = input(v4());
        request.egress.index = 0;
        assert!(worker(&request).is_err());
    }
    #[test]
    fn front_rejects_before_selection_and_never_contains_direct() {
        let request = input(v4());
        let value = parsed(front(&request.listener, 51003, 51005).unwrap());
        assert_eq!(
            value["proxy-groups"][0]["proxies"],
            serde_json::json!(["REJECT", "SLOT-A", "SLOT-B"])
        );
        assert_eq!(value["profile"]["store-selected"], false);
        assert_eq!(value["proxies"][0]["server"], "127.0.0.1");
        assert_eq!(value["proxies"][0]["type"], "socks5");
        assert_eq!(value["rules"][0], "MATCH,OUT");
        assert!(front(&request.listener, 51003, 51003).is_err());
        assert!(front(&request.listener, 51001, 51003).is_err());
    }
    #[test]
    fn writer_never_reallocates_or_accepts_oversize_secrets() {
        use std::io::Write;
        let mut writer = BoundedWriter(Zeroizing::new(Vec::with_capacity(16384)));
        let ptr = writer.0.as_ptr();
        writer.write_all(&[b'x'; 16384]).unwrap();
        assert!(writer.write_all(b"x").is_err());
        assert_eq!(writer.0.len(), 16384);
        assert_eq!(writer.0.as_ptr(), ptr);
    }
    #[test]
    fn route_input_requires_exact_endpoint_alias_identity_and_family() {
        use adapter_platform::physical_attachment::PhysicalBinding;
        let mut request = input(v4());
        let binding = PhysicalBinding {
            luid: 7,
            index: 4,
            ipv4: true,
            ipv6: true,
        };
        let endpoint = "192.0.2.1".parse().unwrap();
        assert!(route_matches(
            &request,
            binding,
            "Ethernet fixture",
            endpoint
        ));
        assert!(!route_matches(&request, binding, "Renamed", endpoint));
        assert!(!route_matches(
            &request,
            binding,
            "Ethernet fixture",
            "192.0.2.2".parse().unwrap()
        ));
        assert!(!route_matches(
            &request,
            PhysicalBinding { luid: 8, ..binding },
            "Ethernet fixture",
            endpoint
        ));
        assert!(!route_matches(
            &request,
            PhysicalBinding {
                index: 5,
                ..binding
            },
            "Ethernet fixture",
            endpoint
        ));
        assert!(!route_matches(
            &request,
            PhysicalBinding {
                ipv4: false,
                ..binding
            },
            "Ethernet fixture",
            endpoint
        ));
        request.transport = Transport::DirectV6 {
            endpoint: "2001:db8::1".parse().unwrap(),
            port: 51820,
        };
        assert!(route_matches(
            &request,
            binding,
            "Ethernet fixture",
            "2001:db8::1".parse().unwrap()
        ));
        assert!(!route_matches(
            &request,
            PhysicalBinding {
                ipv6: false,
                ..binding
            },
            "Ethernet fixture",
            "2001:db8::1".parse().unwrap()
        ));
    }
}

#[cfg(any(windows, test, feature = "windows-api-check"))]
pub mod controller;

#[cfg(any(windows, feature = "windows-api-check"))]
pub mod lifecycle;

#[cfg(any(windows, feature = "windows-api-check"))]
pub mod worker_lifecycle;

#[cfg(any(windows, feature = "windows-api-check"))]
pub mod connection_lifecycle;
#[cfg(any(windows, feature = "windows-api-check"))]
pub mod connection_tunnel;

#[cfg(any(windows, test, feature = "windows-api-check"))]
pub mod dns_transport;

#[cfg(any(windows, test, feature = "windows-api-check"))]
pub mod https_probe;

#[cfg(any(windows, test, feature = "windows-api-check"))]
pub mod canary_batch;
