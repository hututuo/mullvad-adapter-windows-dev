//! Bounded public relay metadata. No network, account, history or readiness claims.
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_RELAYS: usize = 8192;
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
#[derive(Clone, Debug)]
pub struct Relay {
    hostname: String,
    location: String,
    active: bool,
    public_key: String,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    extra_ss: Vec<IpAddr>,
}
impl Relay {
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
    /// Complete authorized candidate pool, not a sweep or readiness claim.
    /// Dedicated addresses and primary-address SS ports coexist. Selection owns
    /// the small per-round window. Retain legacy dedicated UDP/443 candidates.
    pub fn shadowsocks_inlets(&self, relay: &Relay) -> Vec<ShadowsocksInlet> {
        let Some(first) = self
            .shadowsocks_inlet(relay, None)
            .and_then(|inlet| self.authorize_shadowsocks_inlet(relay, inlet.address, inlet.port))
        else {
            return Vec::new();
        };
        let mut inlets = vec![first];
        for address in relay.extra_ss.iter().filter_map(|ip| match ip {
            IpAddr::V4(address) => Some(*address),
            IpAddr::V6(_) => None,
        }) {
            for port in [443, EXTRA_SHADOWSOCKS_PORT] {
                if let Some(inlet) = self.authorize_shadowsocks_inlet(relay, address, port) {
                    if !inlets.contains(&inlet) {
                        inlets.push(inlet);
                    }
                }
            }
        }
        let mut endpoints: HashSet<_> = inlets.iter().map(|i| (i.address, i.port)).collect();
        if let Some(address) = relay.ipv4 {
            for &(low, high) in &self.ss_ports {
                for port in low..=high {
                    if let Some(inlet) = self.authorize_shadowsocks_inlet(relay, address, port) {
                        if endpoints.insert((address, port)) {
                            inlets.push(inlet);
                        }
                    }
                }
            }
        }
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
    /// Capability metadata only, never probe success. Auto order remains ss/v6/v4.
    pub fn transports(&self, relay: &Relay) -> Vec<Transport> {
        if !relay.active {
            return vec![];
        }
        let mut modes = vec![];
        if relay.ipv4.is_some() && !self.ss_ports.is_empty() {
            modes.push(Transport::Shadowsocks);
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
            serde_json::json!(["2001:4860::8", "8.8.4.4"]);
        let catalogue = parse(value).unwrap();
        let relay = &catalogue.relays()[0];
        let extra = catalogue.shadowsocks_inlet(relay, None).unwrap();
        assert_eq!(extra.address, "8.8.4.4".parse::<Ipv4Addr>().unwrap());
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
    fn ss_candidates_combine_all_official_forms_and_keep_primary_ports_in_small_windows() {
        let mut value = fixture();
        value["wireguard"]["relays"][0]["shadowsocks_extra_addr_in"] =
            serde_json::json!(["2001:4860::8", "8.8.8.8", "8.8.4.4", "1.1.1.1"]);
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
        assert!(endpoints.len() > 6);
        assert_eq!(inlets[1].kind, ShadowsocksInletKind::RelayAddress);
        for ip in ["8.8.8.8", "8.8.4.4", "1.1.1.1"] {
            for port in [20484, 443] {
                assert!(endpoints.contains(&(ip.into(), port)));
            }
        }
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
            serde_json::json!(["8.8.4.4", "8.8.4.4", "2001:4860::8"]);
        let catalogue = parse(value).unwrap();
        let inlets = catalogue.shadowsocks_inlets(&catalogue.relays()[0]);
        let dedicated: Vec<_> = inlets
            .iter()
            .filter(|i| i.kind == ShadowsocksInletKind::ExtraAddress)
            .collect();
        assert_eq!(dedicated.len(), 2);
        assert_eq!(
            dedicated.iter().map(|inlet| inlet.port).collect::<Vec<_>>(),
            vec![20484, 443]
        );
        assert!(dedicated
            .iter()
            .all(|inlet| inlet.address == "8.8.4.4".parse::<Ipv4Addr>().unwrap()));
    }
    #[test]
    fn ss_candidates_without_ipv4_extras_keep_all_distinct_published_primary_ports() {
        let mut value = fixture();
        value["wireguard"]["shadowsocks_port_ranges"] =
            serde_json::json!([[51920, 51949], [51900, 51901]]);
        for extras in [serde_json::json!([]), serde_json::json!(["2001:4860::8"])] {
            value["wireguard"]["relays"][0]["shadowsocks_extra_addr_in"] = extras;
            let catalogue = parse(value.clone()).unwrap();
            let relay = &catalogue.relays()[0];
            let pool = catalogue.shadowsocks_inlets(relay);
            let actual: HashSet<_> = pool.iter().map(|i| i.port).collect();
            let expected: HashSet<_> = (51920..=51949).chain(51900..=51901).collect();
            assert_eq!(actual, expected);
            assert_eq!(pool.len(), expected.len());
            assert!(pool
                .iter()
                .all(|i| Some(i.address) == relay.ipv4()
                    && i.kind == ShadowsocksInletKind::RelayAddress));
        }
        value["wireguard"]["relays"][0]["ipv4_addr_in"] = Value::Null;
        value["wireguard"]["relays"][0]["ipv6_addr_in"] = "2001:4860::8".into();
        let catalogue = parse(value).unwrap();
        assert!(catalogue
            .shadowsocks_inlets(&catalogue.relays()[0])
            .is_empty());
    }
    #[test]
    fn ss_candidates_reject_inactive_relays_even_with_ipv4_extras() {
        let mut value = fixture();
        value["wireguard"]["relays"][0]["active"] = false.into();
        value["wireguard"]["relays"][0]["shadowsocks_extra_addr_in"] =
            serde_json::json!(["8.8.4.4"]);
        let catalogue = parse(value).unwrap();
        assert!(catalogue
            .shadowsocks_inlets(&catalogue.relays()[0])
            .is_empty());
    }
    #[test]
    fn withdrawn_or_ipv6_only_ss_extra_does_not_authorize_guessed_ipv4_or_port() {
        let mut value = fixture();
        value["wireguard"]["shadowsocks_port_ranges"] = serde_json::json!([[51900, 51949]]);
        for extras in [serde_json::json!([]), serde_json::json!(["2001:4860::8"])] {
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
            serde_json::json!(["8.8.8.8", "8.8.4.4"]);
        let catalogue = parse(value.clone()).unwrap();
        let relay = &catalogue.relays()[0];
        let original = catalogue
            .authorize_shadowsocks_inlet(relay, "8.8.4.4".parse().unwrap(), 443)
            .unwrap();
        assert_ne!(
            catalogue.shadowsocks_inlet(relay, None).unwrap().address,
            original.address
        );
        assert_eq!(original.kind, ShadowsocksInletKind::ExtraAddress);
        value["wireguard"]["relays"][0]["shadowsocks_extra_addr_in"] =
            serde_json::json!(["8.8.8.8"]);
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
            .authorize_shadowsocks_inlet(relay, "8.8.4.4".parse().unwrap(), 51900)
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
        let mut addresses = vec![Value::String("8.8.4.4".into()); 6];
        addresses.extend((1..=30).map(|n| Value::String(format!("2001:4860::{n:x}"))));
        value["wireguard"]["relays"][0]["shadowsocks_extra_addr_in"] = Value::Array(addresses);
        let catalogue = parse(value).unwrap();
        let relay = &catalogue.relays()[0];
        assert_eq!(relay.extra_shadowsocks().len(), 36);
        assert_eq!(
            catalogue.shadowsocks_inlet(relay, None).unwrap().address,
            "8.8.4.4".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(catalogue.rejected_rows(), 0);
    }
}
