//! TLS-verified, credential-free API access selection. No account request is
//! replayed: only GET api-addrs is used to choose a route before the operation.
use super::*;

const CACHE_CAP: usize = 16 * 1024;
const MAX_ADDRESSES: usize = 16;
const SEED: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(45, 83, 223, 196)), 443);

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiAddressCache {
    addresses: Vec<SocketAddr>,
    last_success: Option<SocketAddr>,
}
impl ApiAddressCache {
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > CACHE_CAP {
            return Err(Error::ResponseTooLarge);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Error::InvalidResponse)?;
        if value.addresses.len() > MAX_ADDRESSES
            || value.addresses.iter().any(|a| !valid_address(*a))
            || value.last_success.is_some_and(|a| !valid_address(a))
        {
            return Err(Error::InvalidResponse);
        }
        Ok(value)
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(self).map_err(|_| Error::InvalidResponse)
    }
    fn candidates(&self) -> Vec<SocketAddr> {
        // Keep the official seed reachable even if every cached address died.
        // Last actual success wins; seed next; remaining authenticated addresses.
        let mut out = Vec::new();
        for address in self
            .last_success
            .into_iter()
            .chain([SEED])
            .chain(self.addresses.iter().copied())
        {
            if valid_address(address) && !out.contains(&address) {
                out.push(address);
            }
        }
        out.truncate(4);
        out
    }
    fn updated(&self, body: &[u8], direct: Option<SocketAddr>) -> Result<Self, Error> {
        if body.len() > CACHE_CAP {
            return Err(Error::ResponseTooLarge);
        }
        let addresses: Vec<SocketAddr> =
            serde_json::from_slice(body).map_err(|_| Error::InvalidResponse)?;
        if addresses.is_empty()
            || addresses.len() > MAX_ADDRESSES
            || addresses.iter().any(|a| !valid_address(*a))
        {
            return Err(Error::InvalidResponse);
        }
        let mut unique = Vec::new();
        for address in addresses {
            if !unique.contains(&address) {
                unique.push(address);
            }
        }
        let last_success = direct.or_else(|| self.last_success.filter(|a| unique.contains(a)));
        Ok(Self {
            addresses: unique,
            last_success,
        })
    }
}
fn valid_address(address: SocketAddr) -> bool {
    if address.port() != 443 {
        return false;
    }
    match address.ip() {
        IpAddr::V4(ip) => {
            let [a, b, _, _] = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_broadcast()
                && !ip.is_multicast()
                && !ip.is_documentation()
                && a != 0
                && a < 224
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 198 && (b == 18 || b == 19))
        }
        IpAddr::V6(ip) => {
            // Public global-unicast only; exclude mapped/local/link-local paths.
            ip.segments()[0] & 0xe000 == 0x2000
                && !ip.is_loopback()
                && !(ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8)
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiAccessRoute {
    Direct,
    IndependentProxy,
    HealthyTunnel,
}
pub struct ApiBootstrap {
    pub client: MullvadClient,
    pub cache: ApiAddressCache,
    pub route: ApiAccessRoute,
}
impl MullvadClient {
    /// Select using bounded, unauthenticated, TLS-verified GETs only. Cache is
    /// written by the caller after success. A failed account/device operation is
    /// never automatically resent on another route.
    pub fn bootstrap(
        cache: &ApiAddressCache,
        independent: Option<BootstrapProxy>,
        healthy_tunnel: Option<BootstrapProxy>,
    ) -> Result<ApiBootstrap, Error> {
        let deadline = Instant::now() + Duration::from_secs(20);
        let direct_deadline = Instant::now() + Duration::from_secs(10);
        let mut error = Error::Unreachable;
        for address in cache.candidates() {
            let until = (Instant::now() + Duration::from_secs(5)).min(direct_deadline);
            if until <= Instant::now() {
                break;
            }
            let client = Self {
                transport: HttpTransport::with_address(address)?,
            };
            match client
                .bootstrap_addresses(until)
                .and_then(|body| cache.updated(&body, Some(address)))
            {
                Ok(cache) => {
                    return Ok(ApiBootstrap {
                        client,
                        cache,
                        route: ApiAccessRoute::Direct,
                    })
                }
                Err(e) => error = e,
            }
        }
        for (proxy, route) in [
            (independent, ApiAccessRoute::IndependentProxy),
            (healthy_tunnel, ApiAccessRoute::HealthyTunnel),
        ] {
            let Some(proxy) = proxy else {
                continue;
            };
            let until = (Instant::now() + Duration::from_secs(5)).min(deadline);
            if until <= Instant::now() {
                break;
            }
            let client = Self::new(proxy)?;
            match client
                .bootstrap_addresses(until)
                .and_then(|body| cache.updated(&body, None))
            {
                Ok(cache) => {
                    return Ok(ApiBootstrap {
                        client,
                        cache,
                        route,
                    })
                }
                Err(e) => error = e,
            }
        }
        Err(error)
    }
    fn bootstrap_addresses(&self, deadline: Instant) -> Result<Vec<u8>, Error> {
        let response = self.transport.request(
            Method::Get,
            "app/v1/api-addrs",
            None,
            None,
            deadline,
            CACHE_CAP,
        )?;
        require_success(&response, false, &[200])?;
        Ok(response.body.to_vec())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cache_prioritizes_actual_success_and_always_includes_official_seed() {
        let cache = ApiAddressCache::decode(br#"{"addresses":["45.83.223.193:443","45.83.223.194:443"],"last_success":"45.83.223.193:443"}"#).unwrap();
        assert_eq!(
            cache.candidates(),
            [
                "45.83.223.193:443".parse().unwrap(),
                SEED,
                "45.83.223.194:443".parse().unwrap()
            ]
        );
        assert_eq!(
            ApiAddressCache::decode(&cache.encode().unwrap())
                .unwrap()
                .candidates(),
            cache.candidates()
        );
    }
    #[test]
    fn malformed_private_empty_and_unbounded_api_lists_never_replace_cache() {
        let cache = ApiAddressCache::default();
        for body in [
            b"[]".as_slice(),
            br#"["127.0.0.1:443"]"#,
            br#"["192.168.1.1:443"]"#,
            br#"["45.83.223.196:80"]"#,
            br#"["[::ffff:127.0.0.1]:443"]"#,
            b"bad json",
        ] {
            assert!(cache.updated(body, None).is_err());
        }
        assert!(cache
            .updated(&serde_json::to_vec(&vec![SEED; 17]).unwrap(), None)
            .is_err());
        assert!(cache.updated(&vec![b' '; CACHE_CAP + 1], None).is_err());
        assert_eq!(cache.candidates(), vec![SEED]);
    }
    #[test]
    fn refreshed_addresses_are_candidates_not_fabricated_successes() {
        let c = ApiAddressCache::default()
            .updated(br#"["45.83.223.193:443","45.83.223.193:443"]"#, Some(SEED))
            .unwrap();
        assert_eq!(c.last_success, Some(SEED));
        assert_eq!(c.addresses.len(), 1);
        let proxy_updated = c.updated(br#"["45.83.223.194:443"]"#, None).unwrap();
        assert_eq!(proxy_updated.last_success, None);
        assert_eq!(proxy_updated.candidates()[0], SEED);
    }
}
