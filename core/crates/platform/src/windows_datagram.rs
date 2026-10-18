//! Owned outer UDP socket. No routes, capture drivers, proxy settings or payload logs.
//! Successful sends prove socket submission, not NIC capture. Receive pktinfo is
//! required before an exchange can witness the selected physical interface.
#[cfg(any(windows, feature = "windows-api-check"))]
use crate::egress::EgressSnapshot;
#[cfg(any(windows, feature = "windows-api-check"))]
use crate::physical_attachment::PhysicalBinding;
use std::{
    io,
    mem::{size_of, zeroed},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
#[cfg(any(windows, feature = "windows-api-check"))]
use std::{
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::Win32::Networking::WinSock::*;

#[cfg(any(windows, feature = "windows-api-check"))]
const CAP: usize = 65507;
const CONTROL_CAP: usize = 128;
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "datagram_binding_not_verified",
    )
}
#[cfg(any(windows, feature = "windows-api-check"))]
fn socket_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}
fn align(n: usize) -> usize {
    (n + size_of::<usize>() - 1) & !(size_of::<usize>() - 1)
}
#[repr(C, align(8))]
struct Control([u8; CONTROL_CAP]);
impl Control {
    fn packet(source: IpAddr, index: u32) -> (Self, usize) {
        let mut control = Self([0; CONTROL_CAP]);
        let start = align(size_of::<CMSGHDR>());
        let (level, kind, len) = match source {
            IpAddr::V4(ip) => {
                let info = IN_PKTINFO {
                    ipi_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(ip.octets()),
                        },
                    },
                    ipi_ifindex: index,
                };
                unsafe {
                    std::ptr::write_unaligned(control.0.as_mut_ptr().add(start).cast(), info);
                }
                (IPPROTO_IP, IP_PKTINFO, size_of::<IN_PKTINFO>())
            }
            IpAddr::V6(ip) => {
                let info = IN6_PKTINFO {
                    ipi6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 { Byte: ip.octets() },
                    },
                    ipi6_ifindex: index,
                };
                unsafe {
                    std::ptr::write_unaligned(control.0.as_mut_ptr().add(start).cast(), info);
                }
                (IPPROTO_IPV6, IPV6_PKTINFO, size_of::<IN6_PKTINFO>())
            }
        };
        unsafe {
            std::ptr::write_unaligned(
                control.0.as_mut_ptr().cast(),
                CMSGHDR {
                    cmsg_len: start + len,
                    cmsg_level: level,
                    cmsg_type: kind,
                },
            );
        }
        (control, start + align(len))
    }
}
/// Exact, bounded ancillary parser. A missing, duplicate, malformed, wrong-family
/// or truncated pktinfo is never treated as physical-path evidence.
fn packet_info(bytes: &[u8], flags: u32, source: IpAddr, index: u32) -> io::Result<()> {
    if flags & (MSG_CTRUNC | MSG_TRUNC) != 0 || bytes.len() > CONTROL_CAP {
        return Err(denied());
    }
    let head = align(size_of::<CMSGHDR>());
    let mut offset = 0;
    let mut found = false;
    while offset < bytes.len() {
        if bytes.len() - offset < head {
            return Err(denied());
        }
        let header =
            unsafe { std::ptr::read_unaligned(bytes.as_ptr().add(offset).cast::<CMSGHDR>()) };
        if header.cmsg_len < head || header.cmsg_len > bytes.len() - offset {
            return Err(denied());
        }
        let data = &bytes[offset + head..offset + header.cmsg_len];
        let expected = match source {
            IpAddr::V4(_) => (IPPROTO_IP, IP_PKTINFO),
            IpAddr::V6(_) => (IPPROTO_IPV6, IPV6_PKTINFO),
        };
        if (header.cmsg_level, header.cmsg_type) == expected {
            if found {
                return Err(denied());
            }
            let matches = match source {
                IpAddr::V4(ip) if data.len() == size_of::<IN_PKTINFO>() => {
                    let info =
                        unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<IN_PKTINFO>()) };
                    info.ipi_ifindex == index
                        && unsafe { info.ipi_addr.S_un.S_addr } == u32::from_ne_bytes(ip.octets())
                }
                IpAddr::V6(ip) if data.len() == size_of::<IN6_PKTINFO>() => {
                    let info =
                        unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<IN6_PKTINFO>()) };
                    info.ipi6_ifindex == index && unsafe { info.ipi6_addr.u.Byte } == ip.octets()
                }
                _ => false,
            };
            if !matches {
                return Err(denied());
            }
            found = true;
        }
        let advance = align(header.cmsg_len);
        // Last cmsg may omit trailing padding; it cannot hide a partial header.
        if advance >= bytes.len() - offset {
            offset = bytes.len();
        } else {
            offset += advance;
        }
    }
    if found {
        Ok(())
    } else {
        Err(denied())
    }
}

struct Address {
    storage: SOCKADDR_STORAGE,
    len: i32,
}
impl Address {
    fn new(address: SocketAddr) -> Self {
        let mut value = Self {
            storage: unsafe { zeroed() },
            len: 0,
        };
        match address {
            SocketAddr::V4(address) => {
                let v = SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: address.port().to_be(),
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(address.ip().octets()),
                        },
                    },
                    sin_zero: [0; 8],
                };
                unsafe {
                    std::ptr::write((&mut value.storage as *mut SOCKADDR_STORAGE).cast(), v);
                }
                value.len = size_of::<SOCKADDR_IN>() as i32;
            }
            SocketAddr::V6(address) => {
                let v = SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_port: address.port().to_be(),
                    sin6_flowinfo: 0,
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 {
                            Byte: address.ip().octets(),
                        },
                    },
                    Anonymous: SOCKADDR_IN6_0 {
                        sin6_scope_id: address.scope_id(),
                    },
                };
                unsafe {
                    std::ptr::write((&mut value.storage as *mut SOCKADDR_STORAGE).cast(), v);
                }
                value.len = size_of::<SOCKADDR_IN6>() as i32;
            }
        }
        value
    }
    fn parse(&self) -> io::Result<SocketAddr> {
        match self.storage.ss_family {
            AF_INET if self.len == size_of::<SOCKADDR_IN>() as i32 => {
                let v = unsafe {
                    std::ptr::read((&self.storage as *const SOCKADDR_STORAGE).cast::<SOCKADDR_IN>())
                };
                Ok(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(
                        unsafe { v.sin_addr.S_un.S_addr }.to_ne_bytes(),
                    )),
                    u16::from_be(v.sin_port),
                ))
            }
            AF_INET6 if self.len == size_of::<SOCKADDR_IN6>() as i32 => {
                let v = unsafe {
                    std::ptr::read(
                        (&self.storage as *const SOCKADDR_STORAGE).cast::<SOCKADDR_IN6>(),
                    )
                };
                if unsafe { v.Anonymous.sin6_scope_id } != 0 || v.sin6_flowinfo != 0 {
                    return Err(denied());
                }
                let ip = Ipv6Addr::from(unsafe { v.sin6_addr.u.Byte });
                if ip.to_ipv4_mapped().is_some() {
                    return Err(denied());
                }
                Ok(SocketAddr::new(IpAddr::V6(ip), u16::from_be(v.sin6_port)))
            }
            _ => Err(denied()),
        }
    }
    #[cfg(any(windows, feature = "windows-api-check"))]
    fn ptr(&self) -> *const SOCKADDR {
        (&self.storage as *const SOCKADDR_STORAGE).cast()
    }
    #[cfg(any(windows, feature = "windows-api-check"))]
    fn mut_ptr(&mut self) -> *mut SOCKADDR {
        (&mut self.storage as *mut SOCKADDR_STORAGE).cast()
    }
}

/// Local marker is not serializable or forgeable outside this module. It is tied
/// to a socket instance, not merely a reused local port or process PID.
#[cfg(any(windows, feature = "windows-api-check"))]
pub struct ExchangeWindow {
    instance: u64,
    started: Instant,
    sent: u64,
    received: u64,
}
#[cfg(any(windows, feature = "windows-api-check"))]
pub struct SocketWitness {
    instance: u64,
    binding: PhysicalBinding,
    source: IpAddr,
    remote: SocketAddr,
    observed: Instant,
}
#[cfg(any(windows, feature = "windows-api-check"))]
impl SocketWitness {
    pub fn observed_at(&self) -> Instant {
        self.observed
    }
}
#[cfg(any(windows, feature = "windows-api-check"))]
pub struct OwnedDatagram {
    instance: u64,
    socket: SOCKET,
    winsock_active: bool,
    recv: LPFN_WSARECVMSG,
    send_msg: LPFN_WSASENDMSG,
    binding: PhysicalBinding,
    source: IpAddr,
    remote: SocketAddr,
    local: SocketAddr,
    sent: u64,
    received: u64,
    last_send: Option<Instant>,
    last_receive: Option<Instant>,
    received_after_send: u64,
}
// Exclusive owner; no duplicate handles, sharing or public raw socket accessor.
#[cfg(any(windows, feature = "windows-api-check"))]
unsafe impl Send for OwnedDatagram {}
#[cfg(any(windows, feature = "windows-api-check"))]
impl Drop for OwnedDatagram {
    fn drop(&mut self) {
        unsafe {
            if self.socket != INVALID_SOCKET {
                closesocket(self.socket);
            }
            if self.winsock_active {
                WSACleanup();
            }
        }
    }
}
#[cfg(any(windows, feature = "windows-api-check"))]
impl OwnedDatagram {
    pub fn open(route: &EgressSnapshot, port: u16) -> io::Result<Self> {
        if !route.is_fresh()
            || port == 0
            || route.binding().index == 0
            || route.binding().index > 0x00ff_ffff
            || route.source().is_ipv4() != route.destination().is_ipv4()
        {
            return Err(denied());
        }
        Self::bind(
            route.binding(),
            route.source(),
            SocketAddr::new(route.destination(), port),
        )
    }
    fn bind(binding: PhysicalBinding, source: IpAddr, remote: SocketAddr) -> io::Result<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let instance = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| denied())?;
        let mut data: WSADATA = unsafe { zeroed() };
        let status = unsafe { WSAStartup(0x202, &mut data) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        if data.wVersion != 0x202 {
            unsafe {
                WSACleanup();
            }
            return Err(denied());
        }
        let socket = unsafe {
            WSASocketW(
                if source.is_ipv4() {
                    AF_INET as i32
                } else {
                    AF_INET6 as i32
                },
                SOCK_DGRAM,
                IPPROTO_UDP,
                null(),
                0,
                WSA_FLAG_NO_HANDLE_INHERIT | WSA_FLAG_OVERLAPPED,
            )
        };
        if socket == INVALID_SOCKET {
            let error = socket_error();
            unsafe {
                WSACleanup();
            }
            return Err(error);
        }
        let mut owned = Self {
            instance,
            socket,
            winsock_active: true,
            recv: None,
            send_msg: None,
            binding,
            source,
            remote,
            local: SocketAddr::new(source, 0),
            sent: 0,
            received: 0,
            last_send: None,
            last_receive: None,
            received_after_send: 0,
        };
        owned.option(SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1)?;
        let (level, unicast, packet) = owned.options();
        if source.is_ipv6() {
            owned.option(IPPROTO_IPV6, IPV6_V6ONLY, 1)?;
        }
        owned.option(
            level,
            unicast,
            if source.is_ipv4() {
                binding.index.to_be()
            } else {
                binding.index
            },
        )?;
        owned.option(level, packet, 1)?;
        let address = Address::new(owned.local);
        if unsafe { bind(socket, address.ptr(), address.len) } == SOCKET_ERROR {
            return Err(socket_error());
        }
        let mut actual = Address {
            storage: unsafe { zeroed() },
            len: size_of::<SOCKADDR_STORAGE>() as i32,
        };
        if unsafe { getsockname(socket, actual.mut_ptr(), &mut actual.len) } == SOCKET_ERROR {
            return Err(socket_error());
        }
        owned.local = actual.parse()?;
        let mut bytes = 0;
        if unsafe {
            WSAIoctl(
                socket,
                SIO_GET_EXTENSION_FUNCTION_POINTER,
                (&WSAID_WSARECVMSG as *const windows_sys::core::GUID).cast(),
                size_of::<windows_sys::core::GUID>() as u32,
                (&mut owned.recv as *mut LPFN_WSARECVMSG).cast(),
                size_of::<LPFN_WSARECVMSG>() as u32,
                &mut bytes,
                null_mut(),
                None,
            )
        } == SOCKET_ERROR
        {
            return Err(socket_error());
        }
        if bytes != size_of::<LPFN_WSARECVMSG>() as u32 || owned.recv.is_none() {
            return Err(denied());
        }
        if unsafe {
            WSAIoctl(
                socket,
                SIO_GET_EXTENSION_FUNCTION_POINTER,
                (&WSAID_WSASENDMSG as *const windows_sys::core::GUID).cast(),
                size_of::<windows_sys::core::GUID>() as u32,
                (&mut owned.send_msg as *mut LPFN_WSASENDMSG).cast(),
                size_of::<LPFN_WSASENDMSG>() as u32,
                &mut bytes,
                null_mut(),
                None,
            )
        } == SOCKET_ERROR
        {
            return Err(socket_error());
        }
        if bytes != size_of::<LPFN_WSASENDMSG>() as u32 || owned.send_msg.is_none() {
            return Err(denied());
        }
        let mut nonblocking = 1;
        if unsafe { ioctlsocket(socket, FIONBIO, &mut nonblocking) } == SOCKET_ERROR {
            return Err(socket_error());
        }
        owned.readback()?;
        Ok(owned)
    }
    fn options(&self) -> (i32, i32, i32) {
        if self.source.is_ipv4() {
            (IPPROTO_IP, IP_UNICAST_IF, IP_PKTINFO)
        } else {
            (IPPROTO_IPV6, IPV6_UNICAST_IF, IPV6_PKTINFO)
        }
    }
    fn option(&self, level: i32, key: i32, value: u32) -> io::Result<()> {
        if unsafe { setsockopt(self.socket, level, key, (&value as *const u32).cast(), 4) }
            == SOCKET_ERROR
        {
            Err(socket_error())
        } else {
            Ok(())
        }
    }
    fn readback(&self) -> io::Result<()> {
        if self.socket == INVALID_SOCKET || !self.winsock_active {
            return Err(denied());
        }
        let mut address = Address {
            storage: unsafe { zeroed() },
            len: size_of::<SOCKADDR_STORAGE>() as i32,
        };
        if unsafe { getsockname(self.socket, address.mut_ptr(), &mut address.len) } == SOCKET_ERROR
        {
            return Err(socket_error());
        }
        if address.parse()? != self.local
            || self.local.ip() != self.source
            || self.local.port() == 0
        {
            return Err(denied());
        }
        let (level, unicast, packet) = self.options();
        let mut options = vec![
            (level, unicast, self.binding.index),
            (level, packet, 1),
            (SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1),
        ];
        if self.source.is_ipv6() {
            options.push((IPPROTO_IPV6, IPV6_V6ONLY, 1));
        }
        for (level, option, expected) in options {
            let mut value = 0u32;
            let mut len = 4;
            if unsafe {
                getsockopt(
                    self.socket,
                    level,
                    option,
                    (&mut value as *mut u32).cast(),
                    &mut len,
                )
            } == SOCKET_ERROR
            {
                return Err(socket_error());
            }
            if len != 4 || value != expected {
                return Err(denied());
            }
        }
        Ok(())
    }
    pub fn validate(&self, route: &EgressSnapshot) -> io::Result<()> {
        if !route.is_fresh()
            || route.binding() != self.binding
            || route.source() != self.source
            || route.destination() != self.remote.ip()
        {
            return Err(denied());
        }
        self.readback()
    }
    pub fn begin_exchange(&self) -> ExchangeWindow {
        ExchangeWindow {
            instance: self.instance,
            started: Instant::now(),
            sent: self.sent,
            received: self.received,
        }
    }
    pub fn witness(
        &self,
        window: &ExchangeWindow,
        route: &EgressSnapshot,
    ) -> io::Result<SocketWitness> {
        self.validate(route)?;
        if !self.has_window_exchange(window) {
            return Err(denied());
        }
        let received = self.last_receive.ok_or_else(denied)?;
        Ok(SocketWitness {
            instance: self.instance,
            binding: self.binding,
            source: self.source,
            remote: self.remote,
            observed: received,
        })
    }
    /// Negative assessment only: a submission in this bounded window plus a
    /// fresh readback. This supplies no receive or positive readiness evidence.
    pub fn submitted_window(
        &self,
        window: &ExchangeWindow,
        route: &EgressSnapshot,
    ) -> io::Result<Instant> {
        self.validate(route)?;
        if window.instance != self.instance
            || window.started.elapsed() > Duration::from_secs(15)
            || self.sent <= window.sent
            || self.last_send.is_none_or(|at| at < window.started)
        {
            return Err(denied());
        }
        Ok(Instant::now())
    }
    fn has_window_exchange(&self, window: &ExchangeWindow) -> bool {
        let (Some(sent), Some(received)) = (self.last_send, self.last_receive) else {
            return false;
        };
        window.instance == self.instance
            && self.sent > window.sent
            && self.received > window.received
            && sent >= window.started
            && received >= window.started
            // An ACK after a received reply does not invalidate that exchange.
            && self.received_after_send > window.sent
            && received.elapsed() < Duration::from_secs(2)
    }
    /// Normal shutdown is checked; Drop is only a last-resort cleanup. The caller
    /// must join the forwarding thread before releasing its peer reservation.
    pub fn close_confirmed(&mut self) -> io::Result<()> {
        if self.socket != INVALID_SOCKET {
            if unsafe { closesocket(self.socket) } == SOCKET_ERROR {
                return Err(socket_error());
            }
            self.socket = INVALID_SOCKET;
        }
        if self.winsock_active {
            if unsafe { WSACleanup() } == SOCKET_ERROR {
                return Err(socket_error());
            }
            self.winsock_active = false;
        }
        Ok(())
    }
    /// Only the still-owned socket may validate its witness. This certifies
    /// submission + receive metadata, not an authenticated request/response;
    /// the caller separately requires the same operation's successful canary.
    pub fn validates(&self, witness: &SocketWitness, route: &EgressSnapshot) -> bool {
        witness.instance == self.instance
            && witness.observed.elapsed() < Duration::from_secs(2)
            && witness.binding == self.binding
            && witness.source == self.source
            && witness.remote == self.remote
            && self.validate(route).is_ok()
    }
    /// None means would-block. Submission can never silently truncate a datagram.
    pub fn send(&mut self, payload: &[u8]) -> io::Result<bool> {
        if payload.is_empty() || payload.len() > CAP {
            return Err(denied());
        }
        let (mut control, len) = Control::packet(self.source, self.binding.index);
        let mut destination = Address::new(self.remote);
        let mut buffer = WSABUF {
            len: payload.len() as u32,
            buf: payload.as_ptr() as *mut u8,
        };
        let message = WSAMSG {
            name: destination.mut_ptr(),
            namelen: destination.len,
            lpBuffers: &mut buffer,
            dwBufferCount: 1,
            Control: WSABUF {
                len: len as u32,
                buf: control.0.as_mut_ptr(),
            },
            dwFlags: 0,
        };
        let mut count = 0;
        let send_msg = self.send_msg.ok_or_else(denied)?;
        if unsafe { send_msg(self.socket, &message, 0, &mut count, null_mut(), None) }
            == SOCKET_ERROR
        {
            let error = socket_error();
            return if error.raw_os_error() == Some(WSAEWOULDBLOCK) {
                Ok(false)
            } else {
                Err(error)
            };
        }
        if count as usize != payload.len() {
            return Err(denied());
        }
        self.sent = self.sent.checked_add(1).ok_or_else(denied)?;
        self.last_send = Some(Instant::now());
        Ok(true)
    }
    /// Only packets from the configured remote with exact pktinfo can escape.
    pub fn receive(&mut self, payload: &mut [u8]) -> io::Result<Option<usize>> {
        if payload.len() < CAP {
            return Err(denied());
        }
        let mut control = Control([0; CONTROL_CAP]);
        let mut sender = Address {
            storage: unsafe { zeroed() },
            len: size_of::<SOCKADDR_STORAGE>() as i32,
        };
        let mut buffer = WSABUF {
            len: CAP as u32,
            buf: payload.as_mut_ptr(),
        };
        let mut message = WSAMSG {
            name: sender.mut_ptr(),
            namelen: sender.len,
            lpBuffers: &mut buffer,
            dwBufferCount: 1,
            Control: WSABUF {
                len: CONTROL_CAP as u32,
                buf: control.0.as_mut_ptr(),
            },
            dwFlags: 0,
        };
        let mut count = 0;
        let receive = self.recv.ok_or_else(denied)?;
        if unsafe { receive(self.socket, &mut message, &mut count, null_mut(), None) }
            == SOCKET_ERROR
        {
            let error = socket_error();
            return if error.raw_os_error() == Some(WSAEWOULDBLOCK) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        sender.len = message.namelen;
        if count == 0
            || count as usize > CAP
            || sender.parse()? != self.remote
            || message.Control.len as usize > CONTROL_CAP
        {
            return Err(denied());
        }
        packet_info(
            &control.0[..message.Control.len as usize],
            message.dwFlags,
            self.source,
            self.binding.index,
        )?;
        self.received = self.received.checked_add(1).ok_or_else(denied)?;
        self.last_receive = Some(Instant::now());
        self.received_after_send = self.sent;
        Ok(Some(count as usize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ancillary_requires_exact_address_interface_and_family() {
        for source in ["192.0.2.4".parse().unwrap(), "2001:db8::4".parse().unwrap()] {
            let (control, len) = Control::packet(source, 7);
            assert!(packet_info(&control.0[..len], 0, source, 7).is_ok());
            assert!(packet_info(&control.0[..len], 0, source, 8).is_err());
            assert!(packet_info(&control.0[..len], MSG_CTRUNC, source, 7).is_err());
            assert!(packet_info(&control.0[..len], MSG_TRUNC, source, 7).is_err());
            assert!(packet_info(&[], 0, source, 7).is_err());
            for truncated in 1..align(size_of::<CMSGHDR>())
                + if source.is_ipv4() {
                    size_of::<IN_PKTINFO>()
                } else {
                    size_of::<IN6_PKTINFO>()
                }
            {
                assert!(packet_info(&control.0[..truncated], 0, source, 7).is_err());
            }
            let mut duplicate = Vec::new();
            duplicate.extend_from_slice(&control.0[..len]);
            duplicate.extend_from_slice(&control.0[..len]);
            assert!(packet_info(&duplicate, 0, source, 7).is_err());
            let wrong: IpAddr = if source.is_ipv4() {
                "192.0.2.5"
            } else {
                "2001:db8::5"
            }
            .parse()
            .unwrap();
            assert!(packet_info(&control.0[..len], 0, wrong, 7).is_err());
        }
    }
    #[test]
    fn sockaddr_roundtrip_and_scope_rejection() {
        for remote in ["192.0.2.4:51900", "[2001:db8::4]:51900"] {
            let remote = remote.parse().unwrap();
            assert_eq!(Address::new(remote).parse().unwrap(), remote);
        }
        assert!(Address::new("[::ffff:192.0.2.4]:51900".parse().unwrap())
            .parse()
            .is_err());
        assert!(Address::new("[fe80::1%7]:51900".parse().unwrap())
            .parse()
            .is_err());
    }
    #[cfg(any(windows, feature = "windows-api-check"))]
    #[test]
    fn native_loopback_datagram_has_exact_pktinfo_and_checked_close() {
        use std::{net::UdpSocket, thread};
        use windows_sys::Win32::NetworkManagement::IpHelper::GetBestInterface;
        // Test-only constructor uses loopback. Public open() still requires a
        // freshly validated physical EgressSnapshot and cannot use this fixture.
        let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        echo.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let remote = echo.local_addr().unwrap();
        let echo_thread = thread::spawn(move || {
            let mut bytes = [0u8; 128];
            let (len, peer) = echo.recv_from(&mut bytes).unwrap();
            assert_eq!(echo.send_to(&bytes[..len], peer).unwrap(), len);
        });
        let mut index = 0;
        assert_eq!(
            unsafe { GetBestInterface(u32::from_ne_bytes([127, 0, 0, 1]), &mut index) },
            0
        );
        let mut socket = OwnedDatagram::bind(
            PhysicalBinding {
                luid: 1,
                index,
                ipv4: true,
                ipv6: false,
            },
            source,
            remote,
        )
        .unwrap();
        socket.readback().unwrap();
        let old_instance = socket.instance;
        let window = socket.begin_exchange();
        assert!(socket.send(b"fixture-only").unwrap());
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut payload = vec![0; CAP];
        let len = loop {
            if let Some(len) = socket.receive(&mut payload).unwrap() {
                break len;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(&payload[..len], b"fixture-only");
        assert_eq!(window.instance, old_instance);
        assert!(socket.last_receive.unwrap() >= socket.last_send.unwrap());
        assert!(socket.has_window_exchange(&window));
        let later = socket.begin_exchange();
        assert!(!socket.has_window_exchange(&later));
        assert!(socket.send(b"later-ack").unwrap());
        assert!(socket.last_send.unwrap() >= socket.last_receive.unwrap());
        assert!(socket.has_window_exchange(&window));
        // A reply from the previous window cannot validate this new send.
        assert!(!socket.has_window_exchange(&later));
        echo_thread.join().unwrap();
        socket.close_confirmed().unwrap();
        socket.close_confirmed().unwrap();
        assert!(socket.readback().is_err());
        let mut replacement = OwnedDatagram::bind(
            PhysicalBinding {
                luid: 1,
                index,
                ipv4: true,
                ipv6: false,
            },
            source,
            remote,
        )
        .unwrap();
        assert_ne!(replacement.instance, old_instance);
        replacement.close_confirmed().unwrap();
    }
}
