//! Point-in-time evidence for an explicitly selected physical egress interface.
use crate::physical_attachment::{
    classify, AddressEvidence, Attachment, InterfaceEvidence, PhysicalBinding,
};
use std::{
    io,
    net::IpAddr,
    time::{Duration, Instant},
};
const FRESH: Duration = Duration::from_secs(2);
pub struct EgressSnapshot {
    binding: PhysicalBinding,
    alias: String,
    source: IpAddr,
    destination: IpAddr,
    started: Instant,
    path: Route,
}
impl EgressSnapshot {
    pub fn binding(&self) -> PhysicalBinding {
        self.binding
    }
    pub fn alias(&self) -> &str {
        &self.alias
    }
    pub fn source(&self) -> IpAddr {
        self.source
    }
    pub fn destination(&self) -> IpAddr {
        self.destination
    }
    /// Compare two independently collected route fingerprints. Freshness and
    /// operation ownership are separate checks made by the caller.
    pub fn same_path(&self, other: &Self) -> bool {
        self.binding == other.binding
            && self.alias == other.alias
            && self.source == other.source
            && self.destination == other.destination
            && self.path == other.path
    }
    pub fn is_fresh(&self) -> bool {
        self.started.elapsed() < FRESH
    }
}
#[derive(Clone, PartialEq, Eq)]
struct Route {
    luid: u64,
    index: u32,
    source: IpAddr,
    prefix: IpAddr,
    prefix_len: u8,
    next_hop: IpAddr,
    next_hop_scope: u32,
    metric: u32,
    loopback: bool,
    lifetime_safe: bool,
}
// A full 2s snapshot window plus a conservative integer-second boundary margin.
// No "currently nonzero" lifetime may authorize evidence after that lifetime.
fn lifetime_covers_snapshot(seconds: u32) -> bool {
    seconds >= 3
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "egress snapshot unavailable or changed",
    )
}
fn public_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_private()
                && !ip.is_multicast()
                && !ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_unicast_link_local()
                && !ip.is_unique_local()
                && !ip.is_multicast()
                && ip.to_ipv4_mapped().is_none()
        }
    }
}
fn contains(prefix: IpAddr, bits: u8, destination: IpAddr) -> bool {
    match (prefix, destination) {
        (IpAddr::V4(prefix), IpAddr::V4(destination)) if bits <= 32 => {
            let mask = u32::MAX.checked_shl(u32::from(32 - bits)).unwrap_or(0);
            u32::from(prefix) & mask == u32::from(destination) & mask
        }
        (IpAddr::V6(prefix), IpAddr::V6(destination)) if bits <= 128 => {
            let mask = u128::MAX.checked_shl(u32::from(128 - bits)).unwrap_or(0);
            u128::from(prefix) & mask == u128::from(destination) & mask
        }
        _ => false,
    }
}
fn validate(
    binding: PhysicalBinding,
    destination: IpAddr,
    first: &(InterfaceEvidence, String),
    last: &(InterfaceEvidence, String),
    address: &AddressEvidence,
    route: &Route,
    again: &Route,
    elapsed: Duration,
) -> io::Result<()> {
    if elapsed >= FRESH
        || first != last
        || route != again
        || !public_destination(destination)
        || binding.luid == 0
        || binding.index == 0
        || first.0.luid != binding.luid
        || first.0.index != binding.index
        || route.luid != binding.luid
        || route.index != binding.index
        || route.loopback
        || !route.lifetime_safe
        || address.luid != binding.luid
        || address.index != binding.index
        || address.address != route.source
        || route.source.is_ipv4() != destination.is_ipv4()
        || route.next_hop.is_ipv4() != destination.is_ipv4()
        || route.next_hop.is_loopback()
        || route.next_hop.is_multicast()
        || route.next_hop == IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
        || (route.next_hop_scope != 0 && route.next_hop_scope != binding.index)
        || !contains(route.prefix, route.prefix_len, destination)
        || (destination.is_ipv4() && !binding.ipv4)
        || (destination.is_ipv6() && !binding.ipv6)
        || first.1.is_empty()
        || first.1.encode_utf16().count() > 256
        || first.1.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    let observation = classify(
        std::slice::from_ref(&first.0),
        std::slice::from_ref(address),
    );
    if observation.attachment != Attachment::Available || observation.bindings.len() != 1 {
        return Err(invalid());
    }
    Ok(())
}
#[cfg(any(windows, feature = "windows-api-check"))]
pub mod windows {
    use super::*;
    use std::{mem::zeroed, ptr::null};
    use windows_sys::Win32::{
        NetworkManagement::{IpHelper::*, Ndis::NET_LUID_LH},
        Networking::WinSock::*,
    };
    fn checked(status: u32) -> io::Result<()> {
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }
    fn sockaddr(ip: IpAddr) -> SOCKADDR_INET {
        let mut address: SOCKADDR_INET = unsafe { zeroed() };
        match ip {
            IpAddr::V4(ip) => {
                address.Ipv4.sin_family = AF_INET;
                address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
            }
            IpAddr::V6(ip) => {
                address.Ipv6.sin6_family = AF_INET6;
                address.Ipv6.sin6_addr.u.Byte = ip.octets();
            }
        }
        address
    }
    fn ip(address: SOCKADDR_INET) -> io::Result<IpAddr> {
        unsafe {
            match address.si_family {
                AF_INET => Ok(IpAddr::V4(
                    address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes().into(),
                )),
                AF_INET6 => Ok(IpAddr::V6(address.Ipv6.sin6_addr.u.Byte.into())),
                _ => Err(invalid()),
            }
        }
    }
    fn interface(binding: PhysicalBinding) -> io::Result<(InterfaceEvidence, String)> {
        let mut row: MIB_IF_ROW2 = unsafe { zeroed() };
        row.InterfaceLuid.Value = binding.luid;
        row.InterfaceIndex = binding.index;
        checked(unsafe { GetIfEntry2(&mut row) })?;
        let end = row.Alias.iter().position(|n| *n == 0).ok_or_else(invalid)?;
        let alias = String::from_utf16(&row.Alias[..end]).map_err(|_| invalid())?;
        Ok((
            crate::physical_attachment::windows::interface_evidence(&row),
            alias,
        ))
    }
    fn route(binding: PhysicalBinding, destination: IpAddr) -> io::Result<(Route, SOCKADDR_INET)> {
        let luid = NET_LUID_LH {
            Value: binding.luid,
        };
        let destination = sockaddr(destination);
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { zeroed() };
        let mut source: SOCKADDR_INET = unsafe { zeroed() };
        checked(unsafe {
            GetBestRoute2(
                &luid,
                binding.index,
                null(),
                &destination,
                0,
                &mut row,
                &mut source,
            )
        })?;
        Ok((
            Route {
                luid: unsafe { row.InterfaceLuid.Value },
                index: row.InterfaceIndex,
                source: ip(source)?,
                prefix: ip(row.DestinationPrefix.Prefix)?,
                prefix_len: row.DestinationPrefix.PrefixLength,
                next_hop: ip(row.NextHop)?,
                next_hop_scope: unsafe {
                    if row.NextHop.si_family == AF_INET6 {
                        row.NextHop.Ipv6.Anonymous.sin6_scope_id
                    } else {
                        0
                    }
                },
                metric: row.Metric,
                loopback: row.Loopback != 0,
                lifetime_safe: lifetime_covers_snapshot(row.ValidLifetime),
            },
            source,
        ))
    }
    /// Read-only and interface-constrained. Call off the domain owner and discard
    /// this snapshot when its caller's token/hint changes; it is not packet proof.
    pub fn snapshot(binding: PhysicalBinding, destination: IpAddr) -> io::Result<EgressSnapshot> {
        let started = Instant::now();
        if !public_destination(destination) || binding.luid == 0 || binding.index == 0 {
            return Err(invalid());
        }
        let first = interface(binding)?;
        let (best, source) = route(binding, destination)?;
        let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { zeroed() };
        row.InterfaceLuid.Value = binding.luid;
        row.InterfaceIndex = binding.index;
        row.Address = source;
        checked(unsafe { GetUnicastIpAddressEntry(&mut row) })?;
        let address = AddressEvidence {
            luid: unsafe { row.InterfaceLuid.Value },
            index: row.InterfaceIndex,
            address: ip(row.Address)?,
            preferred: row.DadState == IpDadStatePreferred
                && lifetime_covers_snapshot(row.ValidLifetime)
                && lifetime_covers_snapshot(row.PreferredLifetime)
                && row.SkipAsSource == 0,
        };
        let (again, _) = route(binding, destination)?;
        let last = interface(binding)?;
        validate(
            binding,
            destination,
            &first,
            &last,
            &address,
            &best,
            &again,
            started.elapsed(),
        )?;
        if started.elapsed() >= FRESH {
            return Err(invalid());
        }
        Ok(EgressSnapshot {
            binding,
            alias: first.1,
            source: best.source,
            destination,
            started,
            path: best,
        })
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn sockaddr_bytes_roundtrip_both_families() {
            for text in ["1.2.3.4", "2001:db8:1234:5678::9"] {
                let address: IpAddr = text.parse().unwrap();
                assert_eq!(ip(sockaddr(address)).unwrap(), address);
            }
        }
        #[test]
        fn native_loopback_route_query_uses_existing_interface_without_packets() {
            let loopback = crate::physical_attachment::windows::interfaces()
                .unwrap()
                .into_iter()
                .find(|row| row.kind == 24)
                .unwrap();
            let binding = PhysicalBinding {
                luid: loopback.luid,
                index: loopback.index,
                ipv4: true,
                ipv6: true,
            };
            let (best, _) = route(binding, "127.0.0.1".parse().unwrap()).unwrap();
            assert_eq!(best.luid, binding.luid);
            assert_eq!(best.index, binding.index);
            assert!(best.source.is_loopback());
            assert!(snapshot(binding, "127.0.0.1".parse().unwrap()).is_err());
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::physical_attachment::Link;
    fn data() -> (
        PhysicalBinding,
        IpAddr,
        (InterfaceEvidence, String),
        AddressEvidence,
        Route,
    ) {
        let binding = PhysicalBinding {
            luid: 9,
            index: 3,
            ipv4: true,
            ipv6: false,
        };
        let interface = (
            InterfaceEvidence {
                luid: 9,
                index: 3,
                hardware: true,
                filter: false,
                endpoint: false,
                tunnel: false,
                kind: 6,
                link: Link::Up,
            },
            "Ethernet".into(),
        );
        let source = "192.168.1.5".parse().unwrap();
        let address = AddressEvidence {
            luid: 9,
            index: 3,
            address: source,
            preferred: true,
        };
        let route = Route {
            luid: 9,
            index: 3,
            source,
            prefix: "0.0.0.0".parse().unwrap(),
            prefix_len: 0,
            next_hop: "192.168.1.1".parse().unwrap(),
            next_hop_scope: 0,
            metric: 10,
            loopback: false,
            lifetime_safe: true,
        };
        (
            binding,
            "1.1.1.1".parse().unwrap(),
            interface,
            address,
            route,
        )
    }
    #[test]
    fn stable_physical_source_route_is_accepted_before_deadline() {
        let (binding, destination, interface, address, route) = data();
        assert!(validate(
            binding,
            destination,
            &interface,
            &interface,
            &address,
            &route,
            &route,
            Duration::from_millis(1999)
        )
        .is_ok());
        assert!(validate(
            binding,
            destination,
            &interface,
            &interface,
            &address,
            &route,
            &route,
            FRESH
        )
        .is_err());
    }
    #[test]
    fn changed_identity_alias_or_route_is_rejected() {
        let (binding, destination, interface, address, route) = data();
        let mut after = interface.clone();
        after.1 = "Renamed".into();
        assert!(validate(
            binding,
            destination,
            &interface,
            &after,
            &address,
            &route,
            &route,
            Duration::ZERO
        )
        .is_err());
        let mut after = interface.clone();
        after.0.luid += 1;
        assert!(validate(
            binding,
            destination,
            &interface,
            &after,
            &address,
            &route,
            &route,
            Duration::ZERO
        )
        .is_err());
        let mut again = route.clone();
        again.metric += 1;
        assert!(validate(
            binding,
            destination,
            &interface,
            &interface,
            &address,
            &route,
            &again,
            Duration::ZERO
        )
        .is_err());
    }
    #[test]
    fn virtual_endpoint_and_unpreferred_source_cannot_prove_egress() {
        let (binding, destination, interface, address, route) = data();
        for change in 0..4 {
            let mut interface = interface.clone();
            match change {
                0 => interface.0.hardware = false,
                1 => interface.0.endpoint = true,
                2 => interface.0.tunnel = true,
                _ => interface.0.filter = true,
            }
            assert!(validate(
                binding,
                destination,
                &interface,
                &interface,
                &address,
                &route,
                &route,
                Duration::ZERO
            )
            .is_err());
        }
        let mut address = address;
        address.preferred = false;
        assert!(validate(
            binding,
            destination,
            &interface,
            &interface,
            &address,
            &route,
            &route,
            Duration::ZERO
        )
        .is_err());
    }
    #[test]
    fn source_and_route_must_belong_to_requested_interface() {
        let (binding, destination, interface, address, route) = data();
        let mut wrong = route.clone();
        wrong.index += 1;
        assert!(validate(
            binding,
            destination,
            &interface,
            &interface,
            &address,
            &wrong,
            &wrong,
            Duration::ZERO
        )
        .is_err());
        let mut wrong = address.clone();
        wrong.luid += 1;
        assert!(validate(
            binding,
            destination,
            &interface,
            &interface,
            &wrong,
            &route,
            &route,
            Duration::ZERO
        )
        .is_err());
        let mut wrong = address;
        wrong.address = "192.168.1.6".parse().unwrap();
        assert!(validate(
            binding,
            destination,
            &interface,
            &interface,
            &wrong,
            &route,
            &route,
            Duration::ZERO
        )
        .is_err());
    }
    #[test]
    fn route_prefix_and_family_are_checked() {
        assert!(contains(
            "0.0.0.0".parse().unwrap(),
            0,
            "1.1.1.1".parse().unwrap()
        ));
        assert!(contains(
            "2001:db8::".parse().unwrap(),
            32,
            "2001:db8:1::1".parse().unwrap()
        ));
        assert!(!contains(
            "2001:db8::".parse().unwrap(),
            32,
            "2001:db9::1".parse().unwrap()
        ));
        assert!(!contains(
            "0.0.0.0".parse().unwrap(),
            33,
            "1.1.1.1".parse().unwrap()
        ));
        assert!(!contains(
            "::".parse().unwrap(),
            129,
            "2001:db8::1".parse().unwrap()
        ));
        let (binding, destination, interface, address, mut route) = data();
        route.prefix = "2.2.2.0".parse().unwrap();
        route.prefix_len = 24;
        assert!(validate(
            binding,
            destination,
            &interface,
            &interface,
            &address,
            &route,
            &route,
            Duration::ZERO
        )
        .is_err());
    }
    #[test]
    fn local_destinations_and_unsafe_aliases_are_rejected() {
        let (binding, _, mut interface, address, route) = data();
        for ip in [
            "127.0.0.1",
            "0.0.0.0",
            "192.168.1.1",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "::ffff:1.1.1.1",
        ] {
            assert!(!public_destination(ip.parse().unwrap()), "{ip}");
        }
        for alias in [String::new(), "secret\ninterface".into(), "x".repeat(257)] {
            interface.1 = alias;
            assert!(validate(
                binding,
                "1.1.1.1".parse().unwrap(),
                &interface,
                &interface,
                &address,
                &route,
                &route,
                Duration::ZERO
            )
            .is_err());
        }
    }
    #[test]
    fn ipv6_source_and_interface_family_are_required() {
        let (mut binding, _, interface, mut address, mut route) = data();
        binding.ipv4 = false;
        binding.ipv6 = true;
        address.address = "2001:db8:1::5".parse().unwrap();
        route.source = address.address;
        route.prefix = "::".parse().unwrap();
        route.next_hop = "fe80::1".parse().unwrap();
        let destination = "2606:4700:4700::1111".parse().unwrap();
        assert!(validate(
            binding,
            destination,
            &interface,
            &interface,
            &address,
            &route,
            &route,
            Duration::ZERO
        )
        .is_ok());
        binding.ipv6 = false;
        assert!(validate(
            binding,
            destination,
            &interface,
            &interface,
            &address,
            &route,
            &route,
            Duration::ZERO
        )
        .is_err());
    }
    #[test]
    fn snapshots_expire_and_invalid_next_hop_scope_is_rejected() {
        let (binding, destination, interface, address, mut route) = data();
        let snapshot = EgressSnapshot {
            binding,
            alias: interface.1.clone(),
            source: address.address,
            destination,
            started: Instant::now() - FRESH,
            path: route.clone(),
        };
        assert!(!snapshot.is_fresh());
        route.next_hop_scope = binding.index + 1;
        assert!(validate(
            binding,
            destination,
            &interface,
            &interface,
            &address,
            &route,
            &route,
            Duration::ZERO
        )
        .is_err());
    }
    #[test]
    fn loopback_expired_or_multicast_routes_never_authorize_launch() {
        let (binding, destination, interface, address, route) = data();
        for change in 0..4 {
            let mut route = route.clone();
            match change {
                0 => route.loopback = true,
                1 => route.lifetime_safe = false,
                2 => route.next_hop = "127.0.0.1".parse().unwrap(),
                _ => route.next_hop = "224.0.0.1".parse().unwrap(),
            }
            assert!(validate(
                binding,
                destination,
                &interface,
                &interface,
                &address,
                &route,
                &route,
                Duration::ZERO
            )
            .is_err());
        }
    }
    #[test]
    fn known_short_route_and_source_lifetimes_are_not_boolean_readiness() {
        for seconds in [0, 1, 2] {
            assert!(!lifetime_covers_snapshot(seconds));
        }
        for seconds in [3, 4, u32::MAX] {
            assert!(lifetime_covers_snapshot(seconds));
        }
    }
    #[test]
    fn review_short_route_lifetime_rejected_before_snapshot_construction() {
        let (binding, destination, interface, address, mut route) = data();
        for seconds in [0, 1, 2] {
            route.lifetime_safe = lifetime_covers_snapshot(seconds);
            assert!(validate(
                binding,
                destination,
                &interface,
                &interface,
                &address,
                &route,
                &route,
                Duration::from_millis(50)
            )
            .is_err());
        }
    }
    #[test]
    fn review_short_source_lifetime_rejected_before_snapshot_construction() {
        let (binding, destination, interface, mut address, route) = data();
        for (valid, preferred) in [
            (0, u32::MAX),
            (1, u32::MAX),
            (2, u32::MAX),
            (u32::MAX, 0),
            (u32::MAX, 1),
            (u32::MAX, 2),
        ] {
            address.preferred =
                lifetime_covers_snapshot(valid) && lifetime_covers_snapshot(preferred);
            assert!(validate(
                binding,
                destination,
                &interface,
                &interface,
                &address,
                &route,
                &route,
                Duration::from_millis(50)
            )
            .is_err());
        }
    }
    #[test]
    fn independent_snapshot_comparison_includes_route_fingerprint() {
        let (binding, destination, interface, address, route) = data();
        let make = |path: Route| EgressSnapshot {
            binding,
            destination,
            alias: interface.1.clone(),
            source: address.address,
            started: Instant::now(),
            path,
        };
        let first = make(route.clone());
        assert!(first.same_path(&make(route.clone())));
        let mut changed = route.clone();
        changed.metric += 1;
        assert!(!first.same_path(&make(changed)));
        let mut changed = route;
        changed.next_hop = "192.168.1.2".parse().unwrap();
        assert!(!first.same_path(&make(changed)));
    }
}
