//! Typed outer path identity. Public relay facts authorize every start/restore.
use adapter_catalogue::{Catalogue, Relay, ShadowsocksInlet};
use adapter_engine_mihomo::Transport;
use std::net::{IpAddr, SocketAddr};

pub(crate) const SS: &str = "wireguard-over-shadowsocks";
pub(crate) const CHAIN: &str = "wireguard-over-shadowsocks-chain";
pub(crate) const V6: &str = "wireguard-ipv6";
pub(crate) const V4: &str = "wireguard-ipv4";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Family {
    V6,
    V4,
}
#[derive(Clone, Copy)]
pub(crate) struct Route {
    pub(crate) transport: Transport,
    pub(crate) chained: bool,
}
impl Route {
    pub(crate) fn ss(inlet: ShadowsocksInlet, chained: bool) -> Self {
        Self {
            transport: Transport::Shadowsocks {
                endpoint: inlet.address,
                port: inlet.port,
            },
            chained,
        }
    }
    pub(crate) fn native(cat: &Catalogue, relay: &Relay, family: Family) -> Option<Self> {
        let (ip, port) = match family {
            Family::V6 => (IpAddr::V6(relay.ipv6()?), 33431),
            Family::V4 => (IpAddr::V4(relay.ipv4()?), 51820),
        };
        Self::authorize(
            cat,
            relay,
            if family == Family::V6 { V6 } else { V4 },
            &SocketAddr::new(ip, port).to_string(),
        )
    }
    pub(crate) fn authorize(
        cat: &Catalogue,
        relay: &Relay,
        kind: &str,
        inlet: &str,
    ) -> Option<Self> {
        if !relay.active() {
            return None;
        }
        let endpoint: SocketAddr = inlet.parse().ok()?;
        if endpoint.port() == 0
            || matches!(endpoint, SocketAddr::V6(a) if a.scope_id() != 0 || a.flowinfo() != 0)
        {
            return None;
        }
        let transport = match (kind, endpoint.ip()) {
            (SS | CHAIN, IpAddr::V4(ip)) => {
                let inlet = cat.authorize_shadowsocks_inlet(relay, ip, endpoint.port())?;
                return Some(Self::ss(inlet, kind == CHAIN));
            }
            (V6, IpAddr::V6(ip))
                if relay.ipv6() == Some(ip) && cat.wireguard_port_allowed(endpoint.port()) =>
            {
                Transport::DirectV6 {
                    endpoint: ip,
                    port: endpoint.port(),
                }
            }
            (V4, IpAddr::V4(ip))
                if relay.ipv4() == Some(ip) && cat.wireguard_port_allowed(endpoint.port()) =>
            {
                Transport::DirectV4 {
                    endpoint: ip,
                    port: endpoint.port(),
                }
            }
            _ => return None,
        };
        Some(Self {
            transport,
            chained: false,
        })
    }
    pub(crate) fn binding(
        self,
        bindings: &[adapter_platform::physical_attachment::PhysicalBinding],
    ) -> Option<adapter_platform::physical_attachment::PhysicalBinding> {
        bindings
            .iter()
            .find(|b| if self.ipv6() { b.ipv6 } else { b.ipv4 })
            .copied()
    }
    pub(crate) fn is_ss(self) -> bool {
        matches!(self.transport, Transport::Shadowsocks { .. })
    }
    pub(crate) fn ipv6(self) -> bool {
        matches!(self.transport, Transport::DirectV6 { .. })
    }
    pub(crate) fn kind(self) -> &'static str {
        match self.transport {
            Transport::DirectV6 { .. } => V6,
            Transport::DirectV4 { .. } => V4,
            Transport::Shadowsocks { .. } if self.chained => CHAIN,
            Transport::Shadowsocks { .. } => SS,
        }
    }
    pub(crate) fn endpoint(self) -> SocketAddr {
        match self.transport {
            Transport::DirectV6 { endpoint, port } => SocketAddr::new(endpoint.into(), port),
            Transport::DirectV4 { endpoint, port } | Transport::Shadowsocks { endpoint, port } => {
                SocketAddr::new(endpoint.into(), port)
            }
        }
    }
}

#[cfg(test)]
#[path = "live_route_tests.rs"]
mod tests;
