//! Read-only attachment evidence. No routes, DNS, sockets or adapter settings change.
use std::net::IpAddr;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Attachment {
    Available,
    Unavailable,
    Unknown,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Link {
    Up,
    Down,
    Unknown,
}
#[derive(Clone, PartialEq, Eq)]
pub struct InterfaceEvidence {
    pub luid: u64,
    pub index: u32,
    pub hardware: bool,
    pub filter: bool,
    pub endpoint: bool,
    pub tunnel: bool,
    pub kind: u32,
    pub link: Link,
}
#[derive(Clone)]
pub struct AddressEvidence {
    pub luid: u64,
    pub index: u32,
    pub address: IpAddr,
    pub preferred: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PhysicalBinding {
    pub luid: u64,
    pub index: u32,
    pub ipv4: bool,
    pub ipv6: bool,
}
pub struct Observation {
    pub attachment: Attachment,
    pub bindings: Vec<PhysicalBinding>,
}
fn unknown() -> Observation {
    Observation {
        attachment: Attachment::Unknown,
        bindings: vec![],
    }
}
fn usable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_unicast_link_local()
                && !ip.is_multicast()
                && ip.to_ipv4_mapped().is_none()
        }
    }
}
/// Complete OS snapshots only. Empty/ambiguous evidence cannot assert an outage.
/// Address presence means attachment, not router WAN/DNS/tunnel readiness.
pub fn classify(interfaces: &[InterfaceEvidence], addresses: &[AddressEvidence]) -> Observation {
    if interfaces.len() > 4096 || addresses.len() > 16384 {
        return unknown();
    }
    let mut luids = std::collections::HashSet::new();
    let mut indices = std::collections::HashSet::new();
    if interfaces.iter().any(|row| {
        row.luid == 0 || row.index == 0 || !luids.insert(row.luid) || !indices.insert(row.index)
    }) {
        return unknown();
    }
    // Tables are read separately: a reused index or unmatched LUID is churn,
    // never evidence that a known physical interface lost all its addresses.
    let identities: std::collections::HashSet<_> =
        interfaces.iter().map(|row| (row.luid, row.index)).collect();
    let mut families = std::collections::HashMap::<(u64, u32), (bool, bool)>::new();
    for address in addresses {
        let key = (address.luid, address.index);
        if !identities.contains(&key) {
            return unknown();
        }
        if address.preferred && usable(address.address) {
            let family = families.entry(key).or_default();
            match address.address {
                IpAddr::V4(_) => family.0 = true,
                IpAddr::V6(_) => family.1 = true,
            }
        }
    }
    let mut physical = 0;
    let mut ambiguous = false;
    let mut bindings = vec![];
    for row in interfaces {
        if !row.hardware || row.filter || row.endpoint || row.tunnel || matches!(row.kind, 24 | 131)
        {
            continue;
        }
        physical += 1;
        // Ethernet, Wi-Fi, WiMax and mobile broadband. Other hardware is unknown.
        if !matches!(row.kind, 6 | 71 | 237 | 243 | 244) || row.link == Link::Unknown {
            ambiguous = true;
            continue;
        }
        if row.link != Link::Up {
            continue;
        }
        let (ipv4, ipv6) = families
            .get(&(row.luid, row.index))
            .copied()
            .unwrap_or_default();
        let binding = PhysicalBinding {
            luid: row.luid,
            index: row.index,
            ipv4,
            ipv6,
        };
        if binding.ipv4 || binding.ipv6 {
            bindings.push(binding);
        }
    }
    bindings.sort_by_key(|b| (b.luid, b.index));
    let attachment = if !bindings.is_empty() {
        Attachment::Available
    } else if physical == 0 || ambiguous {
        Attachment::Unknown
    } else {
        Attachment::Unavailable
    };
    Observation {
        attachment,
        bindings,
    }
}

fn completed_snapshot(
    first: &[InterfaceEvidence],
    addresses: &[AddressEvidence],
    second: &[InterfaceEvidence],
    mut elapsed: impl FnMut() -> std::time::Duration,
) -> Observation {
    if elapsed() >= std::time::Duration::from_secs(2) || first != second {
        return unknown();
    }
    let result = classify(second, addresses);
    if elapsed() >= std::time::Duration::from_secs(2) {
        unknown()
    } else {
        result
    }
}

#[cfg(any(windows, feature = "windows-api-check"))]
pub mod windows {
    use super::*;
    use std::{ffi::c_void, io, ptr::null_mut, time::Instant};
    use windows_sys::Win32::{
        Foundation::ERROR_SUCCESS,
        NetworkManagement::{IpHelper::*, Ndis::*},
        Networking::WinSock::*,
    };
    struct Table(*mut c_void);
    impl Drop for Table {
        fn drop(&mut self) {
            unsafe {
                FreeMibTable(self.0);
            }
        }
    }
    fn invalid() -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, "invalid interface snapshot")
    }
    fn checked(status: u32, pointer: *mut c_void) -> io::Result<Table> {
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if pointer.is_null() {
            return Err(invalid());
        }
        Ok(Table(pointer))
    }
    pub(crate) fn interface_evidence(row: &MIB_IF_ROW2) -> InterfaceEvidence {
        let flags = row.InterfaceAndOperStatusFlags._bitfield;
        let link = if row.OperStatus == IfOperStatusUp
            && row.MediaConnectState == MediaConnectStateConnected
            && flags & (8 | 16 | 32 | 64) == 0
        {
            Link::Up
        } else if row.OperStatus == IfOperStatusDown
            || row.OperStatus == IfOperStatusNotPresent
            || row.OperStatus == IfOperStatusLowerLayerDown
            || row.MediaConnectState == MediaConnectStateDisconnected
        {
            Link::Down
        } else {
            Link::Unknown
        };
        InterfaceEvidence {
            luid: unsafe { row.InterfaceLuid.Value },
            index: row.InterfaceIndex,
            hardware: flags & 1 != 0,
            filter: flags & 2 != 0,
            endpoint: flags & 128 != 0,
            tunnel: row.TunnelType != TUNNEL_TYPE_NONE,
            kind: row.Type,
            link,
        }
    }
    pub(crate) fn interfaces() -> io::Result<Vec<InterfaceEvidence>> {
        let mut pointer = null_mut();
        let _table = checked(unsafe { GetIfTable2(&mut pointer) }, pointer.cast())?;
        let count = unsafe { (*pointer).NumEntries } as usize;
        if count > 4096 {
            return Err(invalid());
        }
        let rows = unsafe {
            std::slice::from_raw_parts(
                std::ptr::addr_of!((*pointer).Table).cast::<MIB_IF_ROW2>(),
                count,
            )
        };
        let mut result = Vec::with_capacity(count);
        for row in rows {
            result.push(interface_evidence(row));
        }
        result.sort_by_key(|row| (row.luid, row.index));
        Ok(result)
    }
    fn addresses() -> io::Result<Vec<AddressEvidence>> {
        let mut pointer = null_mut();
        let _table = checked(
            unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut pointer) },
            pointer.cast(),
        )?;
        let count = unsafe { (*pointer).NumEntries } as usize;
        if count > 16384 {
            return Err(invalid());
        }
        let rows = unsafe {
            std::slice::from_raw_parts(
                std::ptr::addr_of!((*pointer).Table).cast::<MIB_UNICASTIPADDRESS_ROW>(),
                count,
            )
        };
        let mut result = Vec::with_capacity(count);
        for row in rows {
            let address = unsafe {
                match row.Address.si_family {
                    AF_INET => IpAddr::V4(std::net::Ipv4Addr::from(
                        row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
                    )),
                    AF_INET6 => {
                        IpAddr::V6(std::net::Ipv6Addr::from(row.Address.Ipv6.sin6_addr.u.Byte))
                    }
                    _ => return Err(invalid()),
                }
            };
            result.push(AddressEvidence {
                luid: unsafe { row.InterfaceLuid.Value },
                index: row.InterfaceIndex,
                address,
                preferred: row.DadState == IpDadStatePreferred
                    && row.ValidLifetime != 0
                    && row.PreferredLifetime != 0
                    && row.SkipAsSource == 0,
            });
        }
        Ok(result)
    }
    /// Synchronous read-only primitive. Run on one dedicated observer worker.
    /// OS calls cannot be force-cancelled; never invoke on the transaction actor.
    /// Discard late or changing snapshots; no DNS/proxy/internet probes are used.
    pub fn observe() -> io::Result<Observation> {
        let start = Instant::now();
        let first = interfaces()?;
        let addresses = addresses()?;
        let second = interfaces()?;
        Ok(completed_snapshot(&first, &addresses, &second, || {
            start.elapsed()
        }))
    }
    #[cfg(test)]
    mod tests {
        #[test]
        fn raw_endpoint_flag_cannot_become_external_attachment() {
            use super::*;
            let mut raw: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
            raw.InterfaceLuid.Value = 1;
            raw.InterfaceIndex = 1;
            raw.Type = 6;
            raw.OperStatus = IfOperStatusUp;
            raw.MediaConnectState = MediaConnectStateConnected;
            raw.InterfaceAndOperStatusFlags._bitfield = 0x81;
            let evidence = interface_evidence(&raw);
            assert!(evidence.hardware && evidence.endpoint);
            let address = AddressEvidence {
                luid: 1,
                index: 1,
                address: "192.0.2.1".parse().unwrap(),
                preferred: true,
            };
            assert!(classify(&[evidence], &[address]).attachment == Attachment::Unknown);
        }
        #[test]
        fn native_readonly_snapshot_succeeds_without_assuming_internet_access() {
            // Does not print names, MACs, IPs or assert any runner link is physical.
            let result = super::observe().unwrap();
            assert!(result.bindings.len() <= 4096);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn physical(luid: u64, link: Link) -> InterfaceEvidence {
        InterfaceEvidence {
            luid,
            index: luid as u32,
            hardware: true,
            filter: false,
            endpoint: false,
            tunnel: false,
            kind: 71,
            link,
        }
    }
    fn address(luid: u64, text: &str) -> AddressEvidence {
        AddressEvidence {
            luid,
            index: luid as u32,
            address: text.parse().unwrap(),
            preferred: true,
        }
    }
    #[test]
    fn changing_or_late_tables_never_assert_an_outage_or_recovery() {
        let first = [physical(1, Link::Up)];
        let second = [physical(1, Link::Down)];
        assert!(
            completed_snapshot(&first, &[], &second, || std::time::Duration::ZERO).attachment
                == Attachment::Unknown
        );
        assert!(
            completed_snapshot(&first, &[address(1, "192.0.2.1")], &first, || {
                std::time::Duration::from_secs(2)
            })
            .attachment
                == Attachment::Unknown
        );
        assert!(
            completed_snapshot(&first, &[address(1, "192.0.2.1")], &first, || {
                std::time::Duration::from_millis(1999)
            })
            .attachment
                == Attachment::Available
        );
    }
    #[test]
    fn classification_completion_is_included_in_deadline() {
        let interfaces = [physical(1, Link::Up)];
        let mut clock = [1999, 2000].into_iter();
        let result =
            completed_snapshot(&interfaces, &[address(1, "192.0.2.1")], &interfaces, || {
                std::time::Duration::from_millis(clock.next().unwrap())
            });
        assert!(result.attachment == Attachment::Unknown);
        assert!(result.bindings.is_empty());
        assert!(clock.next().is_none());
    }
    #[test]
    fn endpoint_only_hardware_never_masks_real_link_loss() {
        let mut endpoint = physical(2, Link::Up);
        endpoint.endpoint = true;
        assert!(
            classify(
                &[physical(1, Link::Down), endpoint.clone()],
                &[address(2, "192.0.2.1")]
            )
            .attachment
                == Attachment::Unavailable
        );
        let mut changed = endpoint.clone();
        changed.endpoint = false;
        assert!(
            completed_snapshot(&[endpoint], &[address(2, "192.0.2.1")], &[changed], || {
                std::time::Duration::ZERO
            })
            .attachment
                == Attachment::Unknown
        );
    }
    #[test]
    fn virtual_tun_does_not_mask_physical_loss() {
        let mut tun = physical(2, Link::Up);
        tun.hardware = false;
        assert!(
            classify(&[physical(1, Link::Down), tun], &[address(2, "198.18.0.1")]).attachment
                == Attachment::Unavailable
        );
    }
    #[test]
    fn any_supported_physical_ipv4_or_ipv6_can_keep_attachment() {
        let rows = [physical(1, Link::Down), physical(2, Link::Up)];
        for ip in ["192.0.2.8", "2001:db8::1", "fd00::1"] {
            let result = classify(&rows, &[address(2, ip)]);
            assert!(result.attachment == Attachment::Available);
            assert_eq!(result.bindings.len(), 1);
            assert_eq!(result.bindings[0].luid, 2);
        }
    }
    #[test]
    fn empty_ambiguous_or_unsupported_hardware_is_unknown() {
        assert!(classify(&[], &[]).attachment == Attachment::Unknown);
        assert!(classify(&[physical(1, Link::Unknown)], &[]).attachment == Attachment::Unknown);
        let mut other = physical(1, Link::Up);
        other.kind = 1;
        assert!(classify(&[other], &[address(1, "192.0.2.8")]).attachment == Attachment::Unknown);
    }
    #[test]
    fn unusable_or_unpreferred_addresses_cannot_assert_attachment() {
        for ip in [
            "0.0.0.0",
            "127.0.0.1",
            "169.254.1.2",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fe80::1",
            "ff02::1",
            "::ffff:192.0.2.8",
        ] {
            assert!(
                classify(&[physical(1, Link::Up)], &[address(1, ip)]).attachment
                    == Attachment::Unavailable
            );
        }
        let mut pending = address(1, "192.0.2.8");
        pending.preferred = false;
        assert!(
            classify(&[physical(1, Link::Up)], &[pending]).attachment == Attachment::Unavailable
        );
    }
    #[test]
    fn positive_evidence_wins_over_other_ambiguous_links() {
        assert!(
            classify(
                &[physical(1, Link::Unknown), physical(2, Link::Up)],
                &[address(2, "192.0.2.1")]
            )
            .attachment
                == Attachment::Available
        );
        let mut filter = physical(1, Link::Up);
        filter.filter = true;
        assert!(classify(&[filter], &[address(1, "192.0.2.1")]).attachment == Attachment::Unknown);
    }
    #[test]
    fn family_merge_and_duplicate_identity_guards_are_preserved() {
        let rows = [physical(1, Link::Up)];
        let result = classify(
            &rows,
            &[
                address(1, "192.0.2.1"),
                address(1, "2001:db8::1"),
                address(1, "192.0.2.2"),
            ],
        );
        assert!(result.bindings[0].ipv4 && result.bindings[0].ipv6);
        let mut same_index = physical(2, Link::Up);
        same_index.index = 1;
        assert!(classify(&[rows[0].clone(), same_index], &[]).attachment == Attachment::Unknown);
        let mut same_luid = physical(1, Link::Up);
        same_luid.index = 2;
        assert!(classify(&[rows[0].clone(), same_luid], &[]).attachment == Attachment::Unknown);
        assert!(classify(&rows, &[address(2, "192.0.2.1")]).attachment == Attachment::Unknown);
        assert!(classify(&vec![rows[0].clone(); 4097], &[]).attachment == Attachment::Unknown);
        assert!(
            classify(&rows, &vec![address(1, "192.0.2.1"); 16385]).attachment
                == Attachment::Unknown
        );
    }
    #[test]
    fn identity_must_match_both_luid_and_index() {
        let mut stale = address(1, "192.0.2.8");
        stale.index = 7;
        assert!(classify(&[physical(1, Link::Up)], &[stale]).attachment == Attachment::Unknown);
        assert!(
            classify(&[physical(1, Link::Up), physical(1, Link::Down)], &[]).attachment
                == Attachment::Unknown
        );
    }
}
