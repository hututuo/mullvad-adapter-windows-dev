//! Bounded public relay metadata. No network, account, history or readiness claims.
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_RELAYS: usize = 8192;
const MAX_SS_PORT_CANDIDATES: usize = 512;
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Limit,
    Json,
    Root,
    Ports,
    NoValidRelays,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Shadowsocks,
    Quic,
    DirectV6,
    DirectV4,
}
/// Local deterministic default, shared with the established macOS inlet policy.
/// Official dedicated extra SS addresses support all nonzero ports; the primary
/// relay address supports only `shadowsocks_port_ranges`. This is not an upstream
/// fixed-port requirement and must never authorize an invented extra address.
pub const EXTRA_SHADOWSOCKS_PORT: u16 = 20_484;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShadowsocksInletKind {
    ExtraAddress,
    RelayAddress,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShadowsocksInlet {
    pub address: Ipv4Addr,
    pub port: u16,
    pub kind: ShadowsocksInletKind,
}
/// Public official QUIC capability. Token is intentionally excluded from Debug.
#[derive(Clone)]
pub struct Quic {
    addresses: Vec<IpAddr>,
    domain: String,
    token: String,
}
impl std::fmt::Debug for Quic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Quic")
            .field("addresses", &self.addresses)
            .finish_non_exhaustive()
    }
}
impl Quic {
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }
    pub fn domain(&self) -> &str {
        &self.domain
    }
    pub fn token(&self) -> &str {
        &self.token
    }
}
pub const QUIC_PORT: u16 = 443;
fn quic_metadata(row: &Value) -> Option<Quic> {
    let value = row.get("features")?.get("quic")?;
    let domain = value.get("domain")?.as_str()?;
    if domain.is_empty()
        || domain.len() > 253
        || !domain.contains('.')
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return None;
    }
    let token = value.get("token")?.as_str()?;
    if token.is_empty() || token.len() > 4096 || token.chars().any(char::is_control) {
        return None;
    }
    let values = value.get("addr_in")?.as_array()?;
    if values.is_empty() || values.len() > 128 {
        return None;
    }
    let mut addresses = Vec::new();
    for value in values {
        let ip: IpAddr = value.as_str()?.parse().ok()?;
        let valid = match ip {
            IpAddr::V4(ip) => {
                !ip.is_unspecified()
                    && !ip.is_loopback()
                    && !ip.is_private()
                    && !ip.is_link_local()
                    && !ip.is_multicast()
                    && !ip.is_broadcast()
            }
            IpAddr::V6(ip) => {
                !ip.is_unspecified()
                    && !ip.is_loopback()
                    && !ip.is_unique_local()
                    && !ip.is_unicast_link_local()
                    && !ip.is_multicast()
                    && ip.to_ipv4_mapped().is_none()
            }
        };
        if !valid {
            return None;
        }
        if !addresses.contains(&ip) {
            addresses.push(ip);
        }
    }
    Some(Quic {
        addresses,
        domain: domain.into(),
        token: token.into(),
    })
}
#[derive(Clone, Debug)]
pub struct Relay {
    hostname: String,
    location: String,
    active: bool,
    public_key: String,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    extra_ss: Vec<IpAddr>,
    quic: Option<Quic>,
}
impl Relay {
    pub fn quic(&self) -> Option<&Quic> {
        self.quic.as_ref()
    }
    pub fn hostname(&self) -> &str {
        &self.hostname
    }
    pub fn location(&self) -> &str {
        &self.location
    }
    pub fn active(&self) -> bool {
        self.active
    }
    pub fn public_key(&self) -> &str {
        &self.public_key
    }
    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        self.ipv4
    }
    pub fn ipv6(&self) -> Option<Ipv6Addr> {
        self.ipv6
    }
    pub fn extra_shadowsocks(&self) -> &[IpAddr] {
        &self.extra_ss
    }
}
#[derive(Clone)]
pub struct Catalogue {
    relays: Vec<Relay>,
    wg_ports: Vec<(u16, u16)>,
    ss_ports: Vec<(u16, u16)>,
    rejected: usize,
    comparison_facts: Value,
}
impl Catalogue {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(Error::Limit);
        }
        let root: Value = serde_json::from_slice(bytes).map_err(|_| Error::Json)?;
        let wg = root
            .as_object()
            .and_then(|r| r.get("wireguard"))
            .and_then(Value::as_object)
            .ok_or(Error::Root)?;
        let wg_ports = ports(wg.get("port_ranges"))?;
        let ss_ports = ports(wg.get("shadowsocks_port_ranges"))?;
        let rows = wg
            .get("relays")
            .and_then(Value::as_array)
            .ok_or(Error::Root)?;
        if rows.len() > MAX_RELAYS {
            return Err(Error::Limit);
        }
        let mut seen = HashSet::new();
        let mut relays = vec![];
        let mut rejected = 0;
        for row in rows {
            // Reserve a valid name before validating the rest, matching the Ruby
            // first-occurrence rule even when that occurrence is malformed.
            let parsed = (|| {
                let hostname = text(row, "hostname", 255)?;
                if !identifier(hostname) || !seen.insert(hostname.to_owned()) {
                    return None;
                }
                let location = text(row, "location", 64)?;
                if !identifier(location) {
                    return None;
                }
                let active = row.get("active")?.as_bool()?;
                let public_key = text(row, "public_key", 44)?;
                if !key32(public_key) {
                    return None;
                }
                let ipv4 = optional_ip(row, "ipv4_addr_in")?;
                let ipv6 = optional_ip(row, "ipv6_addr_in")?;
                let ipv4 = match ipv4 {
                    None => None,
                    Some(IpAddr::V4(ip)) => Some(ip),
                    _ => return None,
                };
                let ipv6 = match ipv6 {
                    None => None,
                    Some(IpAddr::V6(ip)) => Some(ip),
                    _ => return None,
                };
                if ipv4.is_none() && ipv6.is_none() {
                    return None;
                }
                let extra_ss = match row.get("shadowsocks_extra_addr_in") {
                    None | Some(Value::Null) => vec![],
                    Some(Value::Array(a)) if a.len() <= 128 => a
                        .iter()
                        .map(|v| v.as_str()?.trim().parse().ok())
                        .collect::<Option<Vec<IpAddr>>>()?,
                    _ => return None,
                };
                Some(Relay {
                    hostname: hostname.to_owned(),
                    location: location.to_owned(),
                    active,
                    public_key: public_key.to_owned(),
                    ipv4,
                    ipv6,
                    extra_ss,
                    quic: quic_metadata(row),
                })
            })();
            match parsed {
                Some(relay) => relays.push(relay),
                None => rejected += 1,
            }
        }
        if relays.is_empty() {
            return Err(Error::NoValidRelays);
        }
        let accepted: HashMap<_, _> = relays.iter().map(|r| (r.hostname.clone(), r)).collect();
        let mut comparison_facts = root;
        if let Some(rows) = comparison_facts["wireguard"]["relays"].as_array_mut() {
            let mut retained = HashSet::new();
            rows.retain(|row| {
                row["hostname"].as_str().map(str::trim).is_some_and(|name| {
                    accepted.contains_key(name) && retained.insert(name.to_owned())
                })
            });
            for row in rows.iter_mut() {
                if let Some(relay) = row["hostname"]
                    .as_str()
                    .map(str::trim)
                    .and_then(|name| accepted.get(name))
                {
                    // Only accepted semantic addresses enter bounded IPC lists.
                    row["hostname"] = relay.hostname.clone().into();
                    row["location"] = relay.location.clone().into();
                    row["public_key"] = relay.public_key.clone().into();
                    row["active"] = relay.active.into();
                    row["ipv4_addr_in"] = relay
                        .ipv4
                        .map(|a| Value::String(a.to_string()))
                        .unwrap_or(Value::Null);
                    row["ipv6_addr_in"] = relay
                        .ipv6
                        .map(|a| Value::String(a.to_string()))
                        .unwrap_or(Value::Null);
                    row["shadowsocks_extra_addr_in"] = Value::Array(
                        relay
                            .extra_ss
                            .iter()
                            .map(|a| Value::String(a.to_string()))
                            .collect(),
                    );
                }
            }
        }
        Ok(Self {
            relays,
            wg_ports,
            ss_ports,
            rejected,
            comparison_facts,
        })
    }
    /// Validated public relay facts for an off-owner comparison, never identity data.
    pub fn comparison_facts(&self) -> &Value {
        &self.comparison_facts
    }
    pub fn relays(&self) -> &[Relay] {
        &self.relays
    }
    pub fn rejected_rows(&self) -> usize {
        self.rejected
    }
    /// Exact metadata city only. No hostname substring fallback across cities.
    pub fn active_in_city<'a>(&'a self, city: &'a str) -> impl Iterator<Item = &'a Relay> {
        self.relays
            .iter()
            .filter(move |r| r.active && r.location == city)
    }
    pub fn wireguard_port_allowed(&self, port: u16) -> bool {
        self.wg_ports
            .iter()
            .any(|&(low, high)| low <= port && port <= high)
    }
    pub fn shadowsocks_port_allowed(&self, port: u16) -> bool {
        self.ss_ports
            .iter()
            .any(|&(low, high)| low <= port && port <= high)
    }
    /// Deterministic inlet for a single controlled check. Never assume HTTPS's
    /// port is a Shadowsocks inlet; use only the validated official ranges.
    pub fn first_shadowsocks_port(&self) -> Option<u16> {
        self.ss_ports.iter().map(|&(low, _)| low).min()
    }
    /// Re-authorize an exact saved inlet against current metadata. Ordering of
    /// extra addresses must not turn original-path recovery into a new path.
    pub fn authorize_shadowsocks_inlet(
        &self,
        relay: &Relay,
        address: Ipv4Addr,
        port: u16,
    ) -> Option<ShadowsocksInlet> {
        if !relay.active || port == 0 {
            return None;
        }
        let kind = if relay.extra_ss.contains(&IpAddr::V4(address)) {
            ShadowsocksInletKind::ExtraAddress
        } else if relay.ipv4 == Some(address) && self.shadowsocks_port_allowed(port) {
            ShadowsocksInletKind::RelayAddress
        } else {
            return None;
        };
        Some(ShadowsocksInlet {
            address,
            port,
            kind,
        })
    }
    /// One deterministic inlet, not a sweep or a readiness claim. Prefer a
    /// published extra IPv4 inlet under the established extra-address contract.
    /// An explicit primary-range port remains available for controlled comparisons.
    pub fn shadowsocks_inlet(
        &self,
        relay: &Relay,
        requested_port: Option<u16>,
    ) -> Option<ShadowsocksInlet> {
        if !relay.active || requested_port == Some(0) {
            return None;
        }
        if requested_port.is_none_or(|port| !self.shadowsocks_port_allowed(port)) {
            if let Some(address) = relay.extra_ss.iter().find_map(|ip| match ip {
                IpAddr::V4(address) => Some(*address),
                IpAddr::V6(_) => None,
            }) {
                return Some(ShadowsocksInlet {
                    address,
                    port: requested_port.unwrap_or(EXTRA_SHADOWSOCKS_PORT),
                    kind: ShadowsocksInletKind::ExtraAddress,
                });
            }
        }
        let port = requested_port.or_else(|| self.first_shadowsocks_port())?;
        self.shadowsocks_port_allowed(port)
            .then_some(ShadowsocksInlet {
                address: relay.ipv4?,
                port,
                kind: ShadowsocksInletKind::RelayAddress,
            })
    }
    /// Bounded sample from the official address/port combinations, not a sweep
    /// or readiness claim. Selection owns the small per-round window. Retain
    /// legacy dedicated UDP/443 candidates.
    pub fn shadowsocks_inlets(&self, relay: &Relay) -> Vec<ShadowsocksInlet> {
        let Some(first) = self
            .shadowsocks_inlet(relay, None)
            .and_then(|inlet| self.authorize_shadowsocks_inlet(relay, inlet.address, inlet.port))
        else {
            return Vec::new();
        };
        let mut inlets = vec![first];
        let mut endpoints: HashSet<_> = inlets.iter().map(|i| (i.address, i.port)).collect();
        let mut push = |inlet: ShadowsocksInlet| {
            if endpoints.insert((inlet.address, inlet.port)) {
                inlets.push(inlet);
            }
        };

        // Keep the primary-address default immediately after the preferred
        // inlet so existing recovery ordering remains stable.
        if let (Some(address), Some(port)) = (relay.ipv4, self.first_shadowsocks_port()) {
            if let Some(inlet) = self.authorize_shadowsocks_inlet(relay, address, port) {
                push(inlet);
            }
        }

        let extra_addresses = extra_ipv4_addresses(relay);
        for &address in &extra_addresses {
            for port in [443, EXTRA_SHADOWSOCKS_PORT] {
                if let Some(inlet) = self.authorize_shadowsocks_inlet(relay, address, port) {
                    push(inlet);
                }
            }
        }

        // Preserve every published port for ordinary ranges. Wider ranges use
        // a deterministic bounded sample before the address cross product; the
        // catalogue's 128-extra-address limit caps this pool at 66,304 tuples.
        let sample_ports = self.sampled_shadowsocks_ports();
        let mut addresses = extra_addresses;
        if let Some(address) = relay.ipv4 {
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        for address in addresses {
            for &port in &sample_ports {
                if let Some(inlet) = self.authorize_shadowsocks_inlet(relay, address, port) {
                    push(inlet);
                }
            }
        }
        drop(push);

        if let Some(index) = inlets
            .iter()
            .position(|i| i.kind == ShadowsocksInletKind::RelayAddress)
        {
            if index > 1 {
                let primary = inlets.remove(index);
                inlets.insert(1, primary);
            }
        }
        inlets
    }
    /// Exact count of the candidate combinations represented by the official
    /// address set and port ranges, including legacy extra-address ports. This
    /// avoids deriving catalogue-change counts from the bounded sample.
    pub fn shadowsocks_candidate_count(&self, relay: &Relay) -> usize {
        if !relay.active {
            return 0;
        }
        let extra_addresses = extra_ipv4_addresses(relay);
        let mut addresses: HashSet<_> = extra_addresses.iter().copied().collect();
        if let Some(address) = relay.ipv4 {
            addresses.insert(address);
        }
        if addresses.is_empty() {
            return 0;
        }
        let official_port_count = self
            .normalized_shadowsocks_ranges()
            .iter()
            .map(|&(low, high)| usize::from(high) - usize::from(low) + 1)
            .sum::<usize>();
        let mut count = addresses.len().saturating_mul(official_port_count);
        for _ in extra_addresses {
            for port in [443, EXTRA_SHADOWSOCKS_PORT] {
                if !self.shadowsocks_port_allowed(port) {
                    count = count.saturating_add(1);
                }
            }
        }
        count
    }
    fn sampled_shadowsocks_ports(&self) -> Vec<u16> {
        let ranges = self.normalized_shadowsocks_ranges();
        let total = ranges
            .iter()
            .map(|&(low, high)| usize::from(high) - usize::from(low) + 1)
            .sum::<usize>();
        if total == 0 {
            return Vec::new();
        }
        let sample_count = total.min(MAX_SS_PORT_CANDIDATES);
        let last_index = total - 1;
        let mut samples = Vec::with_capacity(sample_count);
        for index in 0..sample_count {
            let target = if sample_count == 1 {
                0
            } else {
                index * last_index / (sample_count - 1)
            };
            let mut remaining = target;
            for &(low, high) in &ranges {
                let width = usize::from(high) - usize::from(low) + 1;
                if remaining < width {
                    samples.push(low + remaining as u16);
                    break;
                }
                remaining -= width;
            }
        }
        samples
    }
    fn normalized_shadowsocks_ranges(&self) -> Vec<(u16, u16)> {
        let mut ranges = self.ss_ports.clone();
        ranges.sort_unstable();
        let mut merged: Vec<(u16, u16)> = Vec::with_capacity(ranges.len());
        for (low, high) in ranges {
            if let Some(last) = merged.last_mut() {
                if u32::from(low) <= u32::from(last.1) + 1 {
                    last.1 = last.1.max(high);
                    continue;
                }
            }
            merged.push((low, high));
        }
        merged
    }
    /// Capability metadata only, never probe success. Auto order remains ss/v6/v4.
    pub fn transports(&self, relay: &Relay) -> Vec<Transport> {
        if !relay.active {
            return vec![];
        }
        let mut modes = vec![];
        if relay.ipv4.is_some() && !self.ss_ports.is_empty() {
            modes.push(Transport::Shadowsocks);
        }
        if relay.quic.is_some() {
            modes.push(Transport::Quic);
        }
        if relay.ipv6.is_some() && self.wireguard_port_allowed(33431) {
            modes.push(Transport::DirectV6);
        }
        if relay.ipv4.is_some() && self.wireguard_port_allowed(51820) {
            modes.push(Transport::DirectV4);
        }
        modes
    }
}
fn extra_ipv4_addresses(relay: &Relay) -> Vec<Ipv4Addr> {
    let mut seen = HashSet::new();
    relay
        .extra_ss
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(address) => Some(*address),
            IpAddr::V6(_) => None,
        })
        .filter(|address| seen.insert(*address))
        .collect()
}
fn text<'a>(row: &'a Value, field: &str, max: usize) -> Option<&'a str> {
    let s = row.get(field)?.as_str()?.trim();
    (!s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)).then_some(s)
}
fn identifier(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}
fn optional_ip(row: &Value, field: &str) -> Option<Option<IpAddr>> {
    match row.get(field) {
        None | Some(Value::Null) => Some(None),
        Some(Value::String(s)) if s.trim().is_empty() => Some(None),
        Some(Value::String(s)) => s.trim().parse().ok().map(Some),
        _ => None,
    }
}
fn ports(value: Option<&Value>) -> Result<Vec<(u16, u16)>, Error> {
    let a = value.and_then(Value::as_array).ok_or(Error::Ports)?;
    if a.is_empty() || a.len() > 256 {
        return Err(Error::Ports);
    }
    a.iter()
        .map(|v| {
            let pair = v.as_array().filter(|p| p.len() == 2).ok_or(Error::Ports)?;
            let low = pair[0]
                .as_u64()
                .filter(|&n| (1..=65535).contains(&n))
                .ok_or(Error::Ports)? as u16;
            let high = pair[1]
                .as_u64()
                .filter(|&n| (u64::from(low)..=65535).contains(&n))
                .ok_or(Error::Ports)? as u16;
            Ok((low, high))
        })
        .collect()
}
fn key32(s: &str) -> bool {
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
    let b = s.as_bytes();
    b.len() == 44
        && b[43] == b'='
        && b[..43].iter().all(|&b| digit(b).is_some())
        && digit(b[42]).is_some_and(|d| d & 3 == 0)
        && b[..43].iter().any(|&b| b != b'A')
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value {
        serde_json::from_str::<Value>(include_str!("../fixtures/relay-contract.json")).unwrap()[0]
            ["payload"]
            .clone()
    }
    fn parse(value: Value) -> Result<Catalogue, Error> {
        Catalogue::parse(&serde_json::to_vec(&value).unwrap())
    }
    #[test]
    fn shared_ruby_metadata_contract_corpus() {
        let cases: Vec<Value> =
            serde_json::from_str(include_str!("../fixtures/relay-contract.json")).unwrap();
        for case in cases {
            let result = parse(case["payload"].clone());
            assert_eq!(
                result.is_ok(),
                case["accepted"].as_bool().unwrap(),
                "{}",
                case["name"]
            );
            if let Ok(catalogue) = result {
                let hosts: Vec<_> = catalogue.relays().iter().map(|r| r.hostname()).collect();
                assert_eq!(serde_json::to_value(hosts).unwrap(), case["hostnames"]);
                assert_eq!(
                    catalogue.rejected_rows(),
                    case["rejected"].as_u64().unwrap() as usize
                );
                let modes: Vec<Vec<_>> = catalogue
                    .relays()
                    .iter()
                    .map(|r| {
                        catalogue
                            .transports(r)
                            .iter()
                            .map(|t| match t {
                                Transport::Shadowsocks => "ss",
                                Transport::Quic => "quic",
                                Transport::DirectV6 => "ipv6",
                                Transport::DirectV4 => "ipv4",
                            })
                            .collect()
                    })
                    .collect();
                assert_eq!(serde_json::to_value(modes).unwrap(), case["transports"]);
            }
        }
    }
    #[test]
    fn exact_city_and_active_filter_do_not_infer_city_from_hostname() {
        let mut f = fixture();
        f["wireguard"]["relays"][1]["hostname"] = "us-sea-wg-999".into();
        let catalogue = parse(f).unwrap();
        assert_eq!(catalogue.active_in_city("us-sea").count(), 1);
        assert_eq!(catalogue.active_in_city("ca-tor").count(), 1);
        assert_eq!(catalogue.active_in_city("sea").count(), 0);
        assert!(!catalogue.wireguard_port_allowed(0));
        assert!(catalogue.wireguard_port_allowed(33431));
        assert!(!catalogue.wireguard_port_allowed(33432));
        assert!(catalogue.shadowsocks_port_allowed(20484));
        assert!(!catalogue.shadowsocks_port_allowed(21001));
    }
    #[test]
    fn single_ss_check_uses_metadata_ranges_instead_of_https_port() {
        let mut value = fixture();
        value["wireguard"]["shadowsocks_port_ranges"] =
            serde_json::json!([[51920, 51949], [51900, 51901]]);
        let catalogue = parse(value).unwrap();
        assert_eq!(catalogue.first_shadowsocks_port(), Some(51900));
        assert!(catalogue.shadowsocks_port_allowed(51900));
        assert!(!catalogue.shadowsocks_port_allowed(443));
    }
    #[test]
    fn ss_dedicated_inlet_and_primary_ranges_have_separate_contracts() {
        let mut value = fixture();
        value["wireguard"]["shadowsocks_port_ranges"] = serde_json::json!([[51900, 51949]]);
        value["wireguard"]["relays"][0]["shadowsocks_extra_addr_in"] =
            serde_json::json!(["2001:db8::8", "198.51.100.8"]);
        let catalogue = parse(value).unwrap();
        let relay = &catalogue.relays()[0];
        let extra = catalogue.shadowsocks_inlet(relay, None).unwrap();
        assert_eq!(extra.address, "198.51.100.8".parse::<Ipv4Addr>().unwrap());
        assert_eq!(extra.port, EXTRA_SHADOWSOCKS_PORT);
        assert_eq!(extra.kind, ShadowsocksInletKind::ExtraAddress);
        assert_eq!(
            catalogue.shadowsocks_inlet(relay, Some(443)).unwrap().port,
            443
        );
        let primary = catalogue.shadowsocks_inlet(relay, Some(51900)).unwrap();
        assert_eq!(Some(primary.address), relay.ipv4());
        assert_eq!(primary.kind, ShadowsocksInletKind::RelayAddress);
        assert!(catalogue.shadowsocks_inlet(relay, Some(0)).is_none());
    }
    #[test]
    fn ss_candidates_keep_legacy_extra_ports_and_cross_extra_addresses_with_official_ports() {
        let mut value = fixture();
        value["wireguard"]["shadowsocks_port_ranges"] =
            serde_json::json!([[51900, 51902], [52000, 52000]]);
        value["wireguard"]["relays"][0]["shadowsocks_extra_addr_in"] =
            serde_json::json!(["2001:db8::8", "198.51.100.8", "203.0.113.7", "198.51.100.8"]);
        let catalogue = parse(value).unwrap();
        let relay = &catalogue.relays()[0];
        let inlets = catalogue.shadowsocks_inlets(relay);
        assert_eq!(
            inlets.first().copied(),
            catalogue.shadowsocks_inlet(relay, None)
        );
        let endpoints: Vec<_> = inlets
            .iter()
            .map(|inlet| (inlet.address.to_string(), inlet.port))
            .collect();
        assert_eq!(endpoints.len(), inlets.len());
        assert!(endpoints.len() > 6);
        assert_eq!(inlets[1].kind, ShadowsocksInletKind::RelayAddress);
        for ip in ["198.51.100.8", "203.0.113.7"] {
            for port in [443, EXTRA_SHADOWSOCKS_PORT, 51900, 51901, 51902, 52000] {
                assert!(endpoints.contains(&(ip.into(), port)));
                let authorized = catalogue
                    .authorize_shadowsocks_inlet(relay, ip.parse().unwrap(), port)
                    .expect("official extra-address candidate remains authorized");
                assert_eq!(authorized.kind, ShadowsocksInletKind::ExtraAddress);
            }
        }
        assert_eq!(catalogue.shadowsocks_candidate_count(relay), 16);
        assert!(
            catalogue
                .authorize_shadowsocks_inlet(relay, "198.51.100.8".parse().unwrap(), 23456)
                .is_some(),
            "existing extra-address nonzero-port authorization is retained"
        );
        assert!(
            catalogue
                .authorize_shadowsocks_inlet(relay, relay.ipv4().unwrap(), 23456)
                .is_none(),
            "primary-address authorization remains range-bound"
        );
        for inlet in inlets {
            assert_eq!(
                catalogue.authorize_shadowsocks_inlet(relay, inlet.address, inlet.port),
                Some(inlet)
            );
        }
    }
    #[test]
    fn ss_candidates_deduplicate_repeated_extra_addresses_and_the_initial_port() {
        let mut value = fixture();
        value["wireguard"]["relays"][0]["shadowsocks_extra_addr_in"] =
            serde_json::json!(["198.51.100.4", "198.51.100.4", "2001:db8::8"]);
        let catalogue = parse(value).unwrap();
        let inlets = catalogue.shadowsocks_inlets(&catalogue.relays()[0]);
        let dedicated: Vec<_> = inlets
            .iter()
            .filter(|i| {
                i.kind == ShadowsocksInletKind::ExtraAddress
                    && [443, EXTRA_SHADOWSOCKS_PORT].contains(&i.port)
            })
            .collect();
        assert_eq!(dedicated.len(), 2);
        assert_eq!(
            dedicated.iter().map(|inlet| inlet.port).collect::<Vec<_>>(),
            vec![20484, 443]
        );
        assert!(dedicated
            .iter()
            .all(|inlet| inlet.address == "198.51.100.4".parse::<Ipv4Addr>().unwrap()));
    }
    #[test]
    fn ss_candidates_without_ipv4_extras_keep_every_port_in_small_official_ranges() {
        let mut value = fixture();
        value["wireguard"]["shadowsocks_port_ranges"] =
            serde_json::json!([[51920, 51921], [51900, 51901]]);
        for extras in [serde_json::json!([]), serde_json::json!(["2001:db8::8"])] {
            value["wireguard"]["relays"][0]["shadowsocks_extra_addr_in"] = extras;
            let catalogue = parse(value.clone()).unwrap();
            let relay = &catalogue.relays()[0];
            let pool = catalogue.shadowsocks_inlets(relay);
            let actual: HashSet<_> = pool.iter().map(|i| i.port).collect();
            let expected: HashSet<_> = (51920..=51921).chain(51900..=51901).collect();
            assert_eq!(actual, expected);
            assert_eq!(pool.len(), expected.len());
            assert!(pool
                .iter()
                .all(|i| Some(i.address) == relay.ipv4()
                    && i.kind == ShadowsocksInletKind::RelayAddress));
        }
        value["wireguard"]["relays"][0]["ipv4_addr_in"] = Value::Null;
        value["wireguard"]["relays"][0]["ipv6_addr_in"] = "2001:db8::8".into();
        let catalogue = parse(value).unwrap();
        assert!(catalogue
            .shadowsocks_inlets(&catalogue.relays()[0])
            .is_empty());
    }
    #[test]
    fn ss_candidates_include_all_ports_for_ranges_with_at_most_512_ports() {
        let mut value = fixture();
        value["wireguard"]["shadowsocks_port_ranges"] = serde_json::json!([[51900, 52411]]);
        value["wireguard"]["relays"][0]["shadowsocks_extra_addr_in"] =
            serde_json::json!(["198.51.100.47"]);
        let catalogue = parse(value).unwrap();
        let relay = &catalogue.relays()[0];
        let extra: Ipv4Addr = "198.51.100.47".parse().unwrap();
        let pool = catalogue.shadowsocks_inlets(relay);
        let extra_ports: HashSet<_> = pool
            .iter()
            .filter(|i| i.address == extra && catalogue.shadowsocks_port_allowed(i.port))
            .map(|i| i.port)
            .collect();

        let expected: HashSet<u16> = (51900..=52411).collect();
        assert_eq!(extra_ports, expected);
        for port in [51907, 51947] {
            assert!(pool.iter().any(|i| i.address == extra && i.port == port));
            assert!(catalogue
                .authorize_shadowsocks_inlet(relay, extra, port)
                .is_some());
        }
    }
    #[test]
    fn ss_candidate_sampling_bounds_large_port_ranges_and_address_products() {
        let mut value = fixture();
        value["wireguard"]["shadowsocks_port_ranges"] = serde_json::json!([[1, 65535]]);
        value["wireguard"]["relays"][0]["shadowsocks_extra_addr_in"] = Value::Array(
            (1..=128)
                .map(|last| Value::String(format!("198.51.100.{last}")))
                .collect(),
        );
        let catalogue = parse(value).unwrap();
        let relay = &catalogue.relays()[0];
        let pool = catalogue.shadowsocks_inlets(relay);
        let primary_address = relay.ipv4().unwrap();
        let sampled_ports: HashSet<_> = pool
            .iter()
            .filter(|i| i.address == primary_address)
            .filter(|i| catalogue.shadowsocks_port_allowed(i.port))
            .map(|i| i.port)
            .collect();

        assert_eq!(sampled_ports.len(), MAX_SS_PORT_CANDIDATES);
        assert!(pool.len() <= 128 * 2 + 129 * MAX_SS_PORT_CANDIDATES);
        assert!(pool.len() >= 129 * MAX_SS_PORT_CANDIDATES);
        let endpoints: HashSet<_> = pool.iter().map(|i| (i.address, i.port)).collect();
        for last in 1..=128 {
            let address = format!("198.51.100.{last}").parse::<Ipv4Addr>().unwrap();
            for port in &sampled_ports {
                assert!(endpoints.contains(&(address, *port)));
            }
        }
        assert_eq!(catalogue.shadowsocks_candidate_count(relay), 129 * 65_535);
        assert!(pool.iter().all(|inlet| {
            catalogue.authorize_shadowsocks_inlet(relay, inlet.address, inlet.port) == Some(*inlet)
        }));
    }
    #[test]
    fn ss_candidates_reject_inactive_relays_even_with_ipv4_extras() {
        let mut value = fixture();
        value["wireguard"]["relays"][0]["active"] = false.into();
        value["wireguard"]["relays"][0]["shadowsocks_extra_addr_in"] =
            serde_json::json!(["198.51.100.4"]);
        let catalogue = parse(value).unwrap();
        assert!(catalogue
            .shadowsocks_inlets(&catalogue.relays()[0])
            .is_empty());
    }
    #[test]
    fn withdrawn_or_ipv6_only_ss_extra_does_not_authorize_guessed_ipv4_or_port() {
        let mut value = fixture();
        value["wireguard"]["shadowsocks_port_ranges"] = serde_json::json!([[51900, 51949]]);
        for extras in [serde_json::json!([]), serde_json::json!(["2001:db8::8"])] {
            value["wireguard"]["relays"][0]["shadowsocks_extra_addr_in"] = extras;
            let catalogue = parse(value.clone()).unwrap();
            let relay = &catalogue.relays()[0];
            assert!(catalogue.shadowsocks_inlet(relay, Some(20484)).is_none());
            assert!(catalogue.shadowsocks_inlet(relay, Some(443)).is_none());
            let inlet = catalogue.shadowsocks_inlet(relay, None).unwrap();
            assert_eq!(inlet.kind, ShadowsocksInletKind::RelayAddress);
            assert_eq!(inlet.port, 51900);
        }
        value["wireguard"]["relays"][0]["active"] = false.into();
        let catalogue = parse(value).unwrap();
        assert!(catalogue
            .shadowsocks_inlet(&catalogue.relays()[0], None)
            .is_none());
    }
    #[test]
    fn original_extra_is_preserved_after_reordering_but_not_after_withdrawal() {
        let mut value = fixture();
        value["wireguard"]["relays"][0]["shadowsocks_extra_addr_in"] =
            serde_json::json!(["203.0.113.8", "198.51.100.8"]);
        let catalogue = parse(value.clone()).unwrap();
        let relay = &catalogue.relays()[0];
        let original = catalogue
            .authorize_shadowsocks_inlet(relay, "198.51.100.8".parse().unwrap(), 443)
            .unwrap();
        assert_ne!(
            catalogue.shadowsocks_inlet(relay, None).unwrap().address,
            original.address
        );
        assert_eq!(original.kind, ShadowsocksInletKind::ExtraAddress);
        value["wireguard"]["relays"][0]["shadowsocks_extra_addr_in"] =
            serde_json::json!(["203.0.113.8"]);
        let changed = parse(value).unwrap();
        assert!(changed
            .authorize_shadowsocks_inlet(&changed.relays()[0], original.address, original.port)
            .is_none());
    }
    #[test]
    fn original_primary_must_retain_its_published_address_and_port() {
        let mut value = fixture();
        value["wireguard"]["relays"][0]["shadowsocks_extra_addr_in"] = serde_json::json!([]);
        value["wireguard"]["shadowsocks_port_ranges"] = serde_json::json!([[51900, 51949]]);
        let catalogue = parse(value.clone()).unwrap();
        let relay = &catalogue.relays()[0];
        let original = catalogue
            .authorize_shadowsocks_inlet(relay, relay.ipv4().unwrap(), 51900)
            .unwrap();
        assert_eq!(original.kind, ShadowsocksInletKind::RelayAddress);
        assert!(catalogue
            .authorize_shadowsocks_inlet(relay, original.address, 0)
            .is_none());
        assert!(catalogue
            .authorize_shadowsocks_inlet(relay, "198.51.100.8".parse().unwrap(), 51900)
            .is_none());
        value["wireguard"]["shadowsocks_port_ranges"] = serde_json::json!([[51901, 51949]]);
        let changed = parse(value.clone()).unwrap();
        assert!(changed
            .authorize_shadowsocks_inlet(&changed.relays()[0], original.address, original.port)
            .is_none());
        value["wireguard"]["relays"][0]["active"] = false.into();
        let withdrawn = parse(value).unwrap();
        assert!(withdrawn
            .authorize_shadowsocks_inlet(&withdrawn.relays()[0], original.address, 51901)
            .is_none());
    }
    #[test]
    fn strict_schema_deltas_reject_noncanonical_keys_family_coercion_and_ranges() {
        for bad in [
            "",
            "not-a-key",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQF=",
        ] {
            let mut f = fixture();
            f["wireguard"]["relays"].as_array_mut().unwrap().truncate(1);
            f["wireguard"]["relays"][0]["public_key"] = bad.into();
            assert!(matches!(parse(f), Err(Error::NoValidRelays)));
        }
        let mut f = fixture();
        f["wireguard"]["port_ranges"] = serde_json::json!([["33431", 33431]]);
        assert!(matches!(parse(f), Err(Error::Ports)));
        let mut f = fixture();
        f["wireguard"]["relays"].as_array_mut().unwrap().truncate(1);
        f["wireguard"]["relays"][0]["ipv4_addr_in"] = "2001:db8::1".into();
        assert!(matches!(parse(f), Err(Error::NoValidRelays)));
    }
    #[test]
    fn body_row_range_and_extra_address_limits_are_bounded() {
        assert!(matches!(
            Catalogue::parse(&vec![b' '; MAX_BYTES + 1]),
            Err(Error::Limit)
        ));
        let mut f = fixture();
        let row = f["wireguard"]["relays"][0].clone();
        f["wireguard"]["relays"] = Value::Array(vec![row; MAX_RELAYS + 1]);
        assert!(matches!(parse(f), Err(Error::Limit)));
        let mut f = fixture();
        f["wireguard"]["port_ranges"] = Value::Array(vec![serde_json::json!([1, 2]); 257]);
        assert!(matches!(parse(f), Err(Error::Ports)));
        let mut f = fixture();
        f["wireguard"]["relays"].as_array_mut().unwrap().truncate(1);
        f["wireguard"]["relays"][0]["shadowsocks_extra_addr_in"] =
            Value::Array(vec![Value::String("192.0.2.1".into()); 129]);
        assert!(matches!(parse(f), Err(Error::NoValidRelays)));
    }
    #[test]
    fn published_shape_with_thirty_six_extra_addresses_preserves_relay() {
        let mut value = fixture();
        let mut addresses = vec![Value::String("198.51.100.8".into()); 6];
        addresses.extend((1..=30).map(|n| Value::String(format!("2001:db8::{n:x}"))));
        value["wireguard"]["relays"][0]["shadowsocks_extra_addr_in"] = Value::Array(addresses);
        let catalogue = parse(value).unwrap();
        let relay = &catalogue.relays()[0];
        assert_eq!(relay.extra_shadowsocks().len(), 36);
        assert_eq!(
            catalogue.shadowsocks_inlet(relay, None).unwrap().address,
            "198.51.100.8".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(catalogue.rejected_rows(), 0);
    }
}

#[cfg(test)]
mod quic_tests {
    use super::*;
    #[test]
    fn official_quic_requires_complete_valid_metadata_and_redacts_token() {
        let row = serde_json::json!({"features":{"quic":{"addr_in":["192.0.2.5","2001:db8::5"],"domain":"example.mullvad.net","token":"public-but-do-not-log"}}});
        let capability = quic_metadata(&row).unwrap();
        assert_eq!(capability.addresses.len(), 2);
        assert!(!format!("{:?}", capability).contains("public-but-do-not-log"));
        assert!(!format!("{:?}", capability).contains("example.mullvad.net"));
        for bad in [
            serde_json::json!(null),
            serde_json::json!({"addr_in":["127.0.0.1"],"domain":"relay.example","token":"a"}),
            serde_json::json!({"addr_in":["192.0.2.1"],"domain":"relay.example","token":""}),
        ] {
            assert!(quic_metadata(&serde_json::json!({"features":{"quic":bad}})).is_none());
        }
    }
}
