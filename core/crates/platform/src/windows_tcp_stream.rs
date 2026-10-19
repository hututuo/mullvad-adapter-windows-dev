//! An owned, explicitly bound TCP socket; no routing changes or reconnection.
//!
//! A witness certifies bytes exchanged on this retained socket, its configured
//! source/interface, and a fresh matching route. TCP has no UDP receive pktinfo:
//! this is NOT NIC capture or authenticated tunnel readiness. The caller must
//! separately require the same operation's successful tunnel/front canaries.
//! This primitive is not integrated product TCP support.
use std::{
    io,
    mem::{size_of, zeroed},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};
use windows_sys::Win32::Networking::WinSock::*;

#[cfg(any(windows, feature = "windows-api-check"))]
use crate::{
    egress::{windows::snapshot, EgressSnapshot},
    physical_attachment::PhysicalBinding,
};

const FRESH: Duration = Duration::from_secs(2);
const MAX_CONNECT: Duration = Duration::from_secs(15);
#[cfg(any(windows, feature = "windows-api-check"))]
const MAX_IO: usize = 65_537;
fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "tcp_binding_not_verified")
}
fn dword_option(bytes: [u8; 4], length: i32) -> io::Result<u32> {
    if length != 4 {
        return Err(denied());
    }
    Ok(u32::from_ne_bytes(bytes))
}
/// TCP_NODELAY is documented as Boolean but Windows may return one byte. Do
/// not apply this representation rule to interface indices or socket types.
/// A short return must leave the unused, zero-initialized bytes untouched.
fn nodelay_option(bytes: [u8; 4], length: i32) -> io::Result<bool> {
    match length {
        1 if bytes[1..] == [0; 3] => Ok(bytes[0] != 0),
        4 => Ok(u32::from_ne_bytes(bytes) != 0),
        _ => Err(denied()),
    }
}
fn checkpoint(deadline: Instant, cancelled: &impl Fn() -> bool) -> io::Result<()> {
    if cancelled() {
        Err(io::Error::new(io::ErrorKind::Interrupted, "tcp_cancelled"))
    } else if Instant::now() >= deadline {
        Err(io::Error::new(io::ErrorKind::TimedOut, "tcp_deadline"))
    } else {
        Ok(())
    }
}

struct Address {
    storage: SOCKADDR_STORAGE,
    len: i32,
}
impl Address {
    fn new(address: SocketAddr) -> Self {
        let mut result = Self {
            storage: unsafe { zeroed() },
            len: 0,
        };
        match address {
            SocketAddr::V4(address) => {
                let value = SOCKADDR_IN {
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
                    std::ptr::write((&mut result.storage as *mut SOCKADDR_STORAGE).cast(), value);
                }
                result.len = size_of::<SOCKADDR_IN>() as i32;
            }
            SocketAddr::V6(address) => {
                let value = SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_port: address.port().to_be(),
                    sin6_flowinfo: address.flowinfo(),
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
                    std::ptr::write((&mut result.storage as *mut SOCKADDR_STORAGE).cast(), value);
                }
                result.len = size_of::<SOCKADDR_IN6>() as i32;
            }
        }
        result
    }
    fn parse(&self) -> io::Result<SocketAddr> {
        match self.storage.ss_family {
            AF_INET if self.len == size_of::<SOCKADDR_IN>() as i32 => {
                let value = unsafe {
                    std::ptr::read((&self.storage as *const SOCKADDR_STORAGE).cast::<SOCKADDR_IN>())
                };
                Ok(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(
                        unsafe { value.sin_addr.S_un.S_addr }.to_ne_bytes(),
                    )),
                    u16::from_be(value.sin_port),
                ))
            }
            AF_INET6 if self.len == size_of::<SOCKADDR_IN6>() as i32 => {
                let value = unsafe {
                    std::ptr::read(
                        (&self.storage as *const SOCKADDR_STORAGE).cast::<SOCKADDR_IN6>(),
                    )
                };
                let ip = Ipv6Addr::from(unsafe { value.sin6_addr.u.Byte });
                if unsafe { value.Anonymous.sin6_scope_id } != 0
                    || value.sin6_flowinfo != 0
                    || ip.to_ipv4_mapped().is_some()
                {
                    return Err(denied());
                }
                Ok(SocketAddr::new(
                    IpAddr::V6(ip),
                    u16::from_be(value.sin6_port),
                ))
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

/// Not constructible, cloneable or serializable by callers; tied to one socket.
pub struct ExchangeWindow {
    instance: u64,
    started: Instant,
    sent: u64,
    received: u64,
}
pub struct SocketWitness {
    instance: u64,
    observed: Instant,
}
impl SocketWitness {
    pub fn observed_at(&self) -> Instant {
        self.observed
    }
}
struct Flow {
    instance: u64,
    sent: u64,
    received: u64,
    last_send: Option<Instant>,
    last_receive: Option<Instant>,
    received_after_send: u64,
}
impl Flow {
    fn new(instance: u64) -> Self {
        Self {
            instance,
            sent: 0,
            received: 0,
            last_send: None,
            last_receive: None,
            received_after_send: 0,
        }
    }
    fn window(&self) -> ExchangeWindow {
        ExchangeWindow {
            instance: self.instance,
            started: Instant::now(),
            sent: self.sent,
            received: self.received,
        }
    }
    fn sent(&mut self, bytes: usize) -> io::Result<()> {
        self.sent = self.sent.checked_add(bytes as u64).ok_or_else(denied)?;
        self.last_send = Some(Instant::now());
        Ok(())
    }
    fn received(&mut self, bytes: usize) -> io::Result<()> {
        self.received = self.received.checked_add(bytes as u64).ok_or_else(denied)?;
        self.last_receive = Some(Instant::now());
        self.received_after_send = self.sent;
        Ok(())
    }
    fn witness(&self, window: &ExchangeWindow) -> io::Result<SocketWitness> {
        let sent = self.last_send.ok_or_else(denied)?;
        let received = self.last_receive.ok_or_else(denied)?;
        if window.instance != self.instance
            || window.started.elapsed() > MAX_CONNECT
            || self.sent <= window.sent
            || self.received <= window.received
            || self.received_after_send <= window.sent
            || sent < window.started
            || received < window.started
            || received.elapsed() >= FRESH
        {
            return Err(denied());
        }
        Ok(SocketWitness {
            instance: self.instance,
            observed: received,
        })
    }
    fn accepts(&self, witness: &SocketWitness) -> bool {
        witness.instance == self.instance && witness.observed.elapsed() < FRESH
    }
}

#[cfg(any(windows, feature = "windows-api-check"))]
fn socket_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

#[cfg(any(windows, feature = "windows-api-check"))]
struct BoundSocket {
    socket: SOCKET,
    winsock: bool,
    binding: PhysicalBinding,
    source: IpAddr,
    remote: SocketAddr,
    local: SocketAddr,
    connected: bool,
}
#[cfg(any(windows, feature = "windows-api-check"))]
impl BoundSocket {
    fn bind(binding: PhysicalBinding, source: IpAddr, remote: SocketAddr) -> io::Result<Self> {
        if binding.luid == 0
            || binding.index == 0
            || binding.index > 0x00ff_ffff
            || source.is_ipv4() != remote.is_ipv4()
            || remote.port() == 0
            || (source.is_ipv4() && !binding.ipv4)
            || (source.is_ipv6() && !binding.ipv6)
        {
            return Err(denied());
        }
        let mut startup: WSADATA = unsafe { zeroed() };
        let result = unsafe { WSAStartup(0x202, &mut startup) };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        let mut owned = Self {
            socket: INVALID_SOCKET,
            winsock: true,
            binding,
            source,
            remote,
            local: SocketAddr::new(source, 0),
            connected: false,
        };
        if startup.wVersion != 0x202 {
            return Err(denied());
        }
        owned.socket = unsafe {
            WSASocketW(
                if source.is_ipv4() {
                    AF_INET as i32
                } else {
                    AF_INET6 as i32
                },
                SOCK_STREAM,
                IPPROTO_TCP,
                std::ptr::null(),
                0,
                WSA_FLAG_NO_HANDLE_INHERIT | WSA_FLAG_OVERLAPPED,
            )
        };
        if owned.socket == INVALID_SOCKET {
            return Err(socket_error());
        }
        owned.option(SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1)?;
        owned.option(IPPROTO_TCP, TCP_NODELAY, 1)?;
        if source.is_ipv6() {
            owned.option(IPPROTO_IPV6, IPV6_V6ONLY, 1)?;
        }
        // Windows IPv4 sets in network order but gets in host order. IPv6 uses
        // host order. Bind BOTH source and interface before the first connect.
        let (level, key) = owned.interface_option();
        owned.option(
            level,
            key,
            if source.is_ipv4() {
                binding.index.to_be()
            } else {
                binding.index
            },
        )?;
        let address = Address::new(owned.local);
        if unsafe { bind(owned.socket, address.ptr(), address.len) } == SOCKET_ERROR {
            return Err(socket_error());
        }
        owned.local = owned.address(false)?;
        let mut nonblocking = 1;
        if unsafe { ioctlsocket(owned.socket, FIONBIO, &mut nonblocking) } == SOCKET_ERROR {
            return Err(socket_error());
        }
        owned.readback()?;
        Ok(owned)
    }
    fn interface_option(&self) -> (i32, i32) {
        if self.source.is_ipv4() {
            (IPPROTO_IP, IP_UNICAST_IF)
        } else {
            (IPPROTO_IPV6, IPV6_UNICAST_IF)
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
    fn read_option(&self, level: i32, key: i32) -> io::Result<([u8; 4], i32)> {
        let mut value = 0u32;
        let mut length = 4;
        if unsafe {
            getsockopt(
                self.socket,
                level,
                key,
                (&mut value as *mut u32).cast(),
                &mut length,
            )
        } == SOCKET_ERROR
        {
            return Err(socket_error());
        }
        Ok((value.to_ne_bytes(), length))
    }
    fn get_option(&self, level: i32, key: i32) -> io::Result<u32> {
        let (bytes, length) = self.read_option(level, key)?;
        dword_option(bytes, length)
    }
    fn nodelay(&self) -> io::Result<bool> {
        let (bytes, length) = self.read_option(IPPROTO_TCP, TCP_NODELAY)?;
        nodelay_option(bytes, length)
    }
    fn address(&self, peer: bool) -> io::Result<SocketAddr> {
        let mut address = Address {
            storage: unsafe { zeroed() },
            len: size_of::<SOCKADDR_STORAGE>() as i32,
        };
        let result = unsafe {
            if peer {
                getpeername(self.socket, address.mut_ptr(), &mut address.len)
            } else {
                getsockname(self.socket, address.mut_ptr(), &mut address.len)
            }
        };
        if result == SOCKET_ERROR {
            return Err(socket_error());
        }
        address.parse()
    }
    fn readback(&self) -> io::Result<()> {
        if self.socket == INVALID_SOCKET
            || !self.winsock
            || self.local.port() == 0
            || self.local.ip() != self.source
            || self.address(false)? != self.local
            || (self.connected && self.address(true)? != self.remote)
        {
            return Err(denied());
        }
        let (level, key) = self.interface_option();
        for (level, key, expected) in [
            (level, key, self.binding.index),
            (SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1),
            (SOL_SOCKET, SO_TYPE, SOCK_STREAM as u32),
        ] {
            if self.get_option(level, key)? != expected {
                return Err(denied());
            }
        }
        if self.source.is_ipv6() && self.get_option(IPPROTO_IPV6, IPV6_V6ONLY)? != 1 {
            return Err(denied());
        }
        if !self.nodelay()? {
            return Err(denied());
        }
        Ok(())
    }
    fn connect(&mut self, deadline: Instant, cancelled: &impl Fn() -> bool) -> io::Result<()> {
        checkpoint(deadline, cancelled)?;
        self.readback()?;
        let remote = Address::new(self.remote);
        if unsafe { connect(self.socket, remote.ptr(), remote.len) } == SOCKET_ERROR {
            let error = socket_error();
            if !matches!(
                error.raw_os_error(),
                Some(WSAEWOULDBLOCK | WSAEINPROGRESS | WSAEALREADY)
            ) {
                return Err(error);
            }
            loop {
                checkpoint(deadline, cancelled)?;
                let wait = deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis()
                    .clamp(1, 25) as i32;
                let mut poll = WSAPOLLFD {
                    fd: self.socket,
                    events: POLLWRNORM,
                    revents: 0,
                };
                let result = unsafe { WSAPoll(&mut poll, 1, wait) };
                if result == SOCKET_ERROR {
                    let error = socket_error();
                    if error.raw_os_error() == Some(WSAEINTR) {
                        continue;
                    }
                    return Err(error);
                }
                if result == 0 {
                    continue;
                }
                let error = self.get_option(SOL_SOCKET, SO_ERROR)?;
                if error != 0 {
                    return Err(io::Error::from_raw_os_error(error as i32));
                }
                if poll.revents & (POLLERR | POLLHUP | POLLNVAL) != 0
                    || poll.revents & POLLWRNORM == 0
                {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "tcp_connect_failed",
                    ));
                }
                break;
            }
        }
        checkpoint(deadline, cancelled)?;
        self.connected = true;
        self.readback()
    }
    fn close(&mut self) -> io::Result<()> {
        self.connected = false;
        if self.socket != INVALID_SOCKET {
            if unsafe { closesocket(self.socket) } == SOCKET_ERROR {
                return Err(socket_error());
            }
            self.socket = INVALID_SOCKET;
        }
        if self.winsock {
            if unsafe { WSACleanup() } == SOCKET_ERROR {
                return Err(socket_error());
            }
            self.winsock = false;
        }
        Ok(())
    }
}
#[cfg(any(windows, feature = "windows-api-check"))]
impl Drop for BoundSocket {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(any(windows, feature = "windows-api-check"))]
pub struct OwnedTcpStream {
    socket: BoundSocket,
    baseline: EgressSnapshot,
    flow: Flow,
    poisoned: bool,
}
#[cfg(any(windows, feature = "windows-api-check"))]
impl OwnedTcpStream {
    /// The caller obtains `route` inside its current BoundNetwork operation and
    /// supplies that operation's cancellation monitor here. Connect is bounded
    /// to min(deadline, now + 15s); no retries, DNS or alternate route are used.
    pub fn connect(
        route: &EgressSnapshot,
        port: u16,
        deadline: Instant,
        cancelled: impl Fn() -> bool,
    ) -> io::Result<Self> {
        let deadline = deadline.min(Instant::now() + MAX_CONNECT);
        checkpoint(deadline, &cancelled)?;
        if !route.is_fresh() || port == 0 {
            return Err(denied());
        }
        let baseline = snapshot(route.binding(), route.destination())?;
        checkpoint(deadline, &cancelled)?;
        if !baseline.is_fresh() || !route.is_fresh() || !baseline.same_path(route) {
            return Err(denied());
        }
        let mut socket = BoundSocket::bind(
            route.binding(),
            route.source(),
            SocketAddr::new(route.destination(), port),
        )?;
        checkpoint(deadline, &cancelled)?;
        if !baseline.is_fresh() {
            return Err(denied());
        }
        socket.connect(deadline, &cancelled)?;
        let again = snapshot(route.binding(), route.destination())?;
        checkpoint(deadline, &cancelled)?;
        if !again.is_fresh() || !baseline.same_path(&again) {
            return Err(denied());
        }
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let instance = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| denied())?;
        Ok(Self {
            socket,
            baseline,
            flow: Flow::new(instance),
            poisoned: false,
        })
    }
    /// No fresh route may change the source, destination, physical identity or
    /// path fingerprint of this still-owned socket. A change requires rebuilding.
    pub fn validate(&self, route: &EgressSnapshot) -> io::Result<()> {
        if self.poisoned
            || !self.socket.connected
            || !route.is_fresh()
            || !self.baseline.same_path(route)
        {
            return Err(denied());
        }
        self.socket.readback()?;
        if !route.is_fresh() {
            return Err(denied());
        }
        Ok(())
    }
    fn guard(
        &mut self,
        route: &EgressSnapshot,
        deadline: Instant,
        cancelled: &impl Fn() -> bool,
    ) -> io::Result<()> {
        let result = checkpoint(deadline, cancelled).and_then(|()| self.validate(route));
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    /// One nonblocking call; returns a partial byte count or WouldBlock. Callers
    /// retain the offset, bound their loop, and refresh route/operation guards.
    /// Fatal errors, expired guards and EOF poison the stream; never reconnect.
    pub fn write(
        &mut self,
        bytes: &[u8],
        route: &EgressSnapshot,
        deadline: Instant,
        cancelled: impl Fn() -> bool,
    ) -> io::Result<usize> {
        self.guard(route, deadline, &cancelled)?;
        if bytes.is_empty() || bytes.len() > MAX_IO {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let count = unsafe { send(self.socket.socket, bytes.as_ptr(), bytes.len() as i32, 0) };
        if count == SOCKET_ERROR {
            return self.io_error();
        }
        if count == 0 {
            self.poisoned = true;
            return Err(io::ErrorKind::WriteZero.into());
        }
        self.flow.sent(count as usize)?;
        self.guard(route, deadline, &cancelled)?;
        Ok(count as usize)
    }
    /// One nonblocking call. `Ok(0)` is terminal EOF, never readiness evidence.
    pub fn read(
        &mut self,
        bytes: &mut [u8],
        route: &EgressSnapshot,
        deadline: Instant,
        cancelled: impl Fn() -> bool,
    ) -> io::Result<usize> {
        self.guard(route, deadline, &cancelled)?;
        if bytes.is_empty() || bytes.len() > MAX_IO {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let count = unsafe {
            recv(
                self.socket.socket,
                bytes.as_mut_ptr(),
                bytes.len() as i32,
                0,
            )
        };
        if count == SOCKET_ERROR {
            return self.io_error();
        }
        if count == 0 {
            self.poisoned = true;
            return Ok(0);
        }
        self.flow.received(count as usize)?;
        self.guard(route, deadline, &cancelled)?;
        Ok(count as usize)
    }
    fn io_error(&mut self) -> io::Result<usize> {
        let error = socket_error();
        if error.raw_os_error() == Some(WSAEWOULDBLOCK) {
            Err(io::ErrorKind::WouldBlock.into())
        } else if error.raw_os_error() == Some(WSAEINTR) {
            Err(io::ErrorKind::Interrupted.into())
        } else {
            self.poisoned = true;
            Err(error)
        }
    }
    pub fn begin_exchange(&self) -> ExchangeWindow {
        self.flow.window()
    }
    pub fn witness(
        &self,
        window: &ExchangeWindow,
        route: &EgressSnapshot,
    ) -> io::Result<SocketWitness> {
        self.validate(route)?;
        self.flow.witness(window)
    }
    pub fn validates(&self, witness: &SocketWitness, route: &EgressSnapshot) -> bool {
        self.flow.accepts(witness) && self.validate(route).is_ok()
    }
    /// Fresh readback after bytes submitted; negative assessment only.
    pub fn submitted_window(
        &self,
        window: &ExchangeWindow,
        route: &EgressSnapshot,
    ) -> io::Result<Instant> {
        self.validate(route)?;
        if window.instance != self.flow.instance
            || window.started.elapsed() > MAX_CONNECT
            || self.flow.sent <= window.sent
            || self.flow.last_send.is_none_or(|sent| sent < window.started)
        {
            return Err(denied());
        }
        Ok(Instant::now())
    }
    pub fn close_confirmed(&mut self) -> io::Result<()> {
        self.poisoned = true;
        self.socket.close()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nodelay_accepts_boolean_widths_but_never_shortens_dword_options() {
        for bytes in [[1, 0, 0, 0], [u8::MAX, 0, 0, 0]] {
            assert!(nodelay_option(bytes, 1).unwrap());
            assert!(dword_option(bytes, 1).is_err());
        }
        assert!(!nodelay_option([0; 4], 1).unwrap());
        for value in [1u32, u32::MAX] {
            let bytes = value.to_ne_bytes();
            assert!(nodelay_option(bytes, 4).unwrap());
            assert_eq!(dword_option(bytes, 4).unwrap(), value);
        }
        assert!(!nodelay_option([0; 4], 4).unwrap());
        for length in [-1, 0, 2, 3, 5] {
            assert!(nodelay_option([1, 0, 0, 0], length).is_err());
            assert!(dword_option([1, 0, 0, 0], length).is_err());
        }
        for bytes in [[1, 1, 0, 0], [1, 0, 1, 0], [1, 0, 0, 1]] {
            assert!(nodelay_option(bytes, 1).is_err());
        }
        // The actual Windows loopback evidence was length=1/value=1 for
        // TCP_NODELAY, but length=4/value=1 for UNICAST_IF and SO_TYPE.
        assert_eq!(dword_option(1u32.to_ne_bytes(), 4).unwrap(), 1);
    }
    #[test]
    fn addresses_require_exact_family_length_and_unscoped_ipv6() {
        for text in ["192.0.2.4:5001", "[2001:db8::4]:443"] {
            let address = text.parse().unwrap();
            let mut native = Address::new(address);
            assert_eq!(native.parse().unwrap(), address);
            native.len -= 1;
            assert!(native.parse().is_err());
        }
        for text in ["[::ffff:192.0.2.4]:5001", "[fe80::1%3]:5001"] {
            assert!(Address::new(text.parse().unwrap()).parse().is_err());
        }
    }
    #[test]
    fn a_witness_needs_receive_after_send_in_its_own_window() {
        let mut flow = Flow::new(1);
        flow.sent(5).unwrap();
        flow.received(5).unwrap();
        let window = flow.window();
        assert!(flow.witness(&window).is_err());
        flow.received(5).unwrap();
        flow.sent(5).unwrap();
        assert!(flow.witness(&window).is_err());
        flow.received(5).unwrap();
        assert!(flow.witness(&window).is_ok());
    }
    #[test]
    fn reused_tuple_cannot_reuse_instance_or_stale_witness() {
        let mut original = Flow::new(1);
        let window = original.window();
        original.sent(4).unwrap();
        original.received(4).unwrap();
        let mut witness = original.witness(&window).unwrap();
        assert!(original.accepts(&witness));
        let mut replacement = Flow::new(2);
        replacement.sent(99).unwrap();
        replacement.received(99).unwrap();
        assert!(replacement.witness(&window).is_err());
        assert!(!replacement.accepts(&witness));
        witness.observed = Instant::now() - FRESH;
        assert!(!original.accepts(&witness));
        original.last_receive = Some(Instant::now() - FRESH);
        assert!(original.witness(&window).is_err());
    }
    #[test]
    fn cancellation_and_deadline_are_distinct() {
        assert_eq!(
            checkpoint(Instant::now() + FRESH, &|| true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(
            checkpoint(Instant::now(), &|| false).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    /// Exercises Windows socket options and nonblocking connect/data/close on
    /// loopback only. This cannot issue a public physical-route witness.
    #[cfg(windows)]
    #[test]
    fn native_bound_loopback_tcp_roundtrip_is_not_physical_egress_acceptance() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            thread,
        };
        let interface = crate::physical_attachment::windows::interfaces()
            .unwrap()
            .into_iter()
            .find(|row| row.kind == 24)
            .unwrap();
        let binding = PhysicalBinding {
            luid: interface.luid,
            index: interface.index,
            ipv4: true,
            ipv6: false,
        };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut socket = BoundSocket::bind(
            binding,
            Ipv4Addr::LOCALHOST.into(),
            listener.local_addr().unwrap(),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        assert_eq!(
            socket.connect(deadline, &|| true).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(!socket.connected);
        socket.connect(deadline, &|| false).unwrap();
        socket.readback().unwrap();
        let (mut peer, _) = loop {
            checkpoint(deadline, &|| false).unwrap();
            match listener.accept() {
                Ok(peer) => break peer,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1))
                }
                Err(error) => panic!("loopback accept: {error:?}"),
            }
        };
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        loop {
            checkpoint(deadline, &|| false).unwrap();
            let count = unsafe { send(socket.socket, b"a".as_ptr(), 1, 0) };
            if count == 1 {
                break;
            }
            assert_eq!(socket_error().raw_os_error(), Some(WSAEWOULDBLOCK));
            thread::sleep(Duration::from_millis(1));
        }
        let mut byte = [0];
        peer.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"a");
        peer.write_all(b"b").unwrap();
        loop {
            checkpoint(deadline, &|| false).unwrap();
            let count = unsafe { recv(socket.socket, byte.as_mut_ptr(), 1, 0) };
            if count == 1 {
                break;
            }
            assert_eq!(socket_error().raw_os_error(), Some(WSAEWOULDBLOCK));
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(byte, *b"b");
        socket.readback().unwrap();
        socket.close().unwrap();
        assert!(socket.readback().is_err());
        socket.close().unwrap();
    }
}
