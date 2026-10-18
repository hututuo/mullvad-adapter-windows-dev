//! Proof that an established loopback TCP peer belongs to a retained live process.
use std::{
    io,
    mem::{offset_of, size_of},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
    ptr::null_mut,
};
use windows_sys::Win32::{
    Foundation::*,
    NetworkManagement::IpHelper::*,
    Networking::WinSock::{AF_INET, AF_INET6},
    System::Threading::*,
};

pub struct ControllerOwner(HANDLE);
// A duplicated process handle is only queried, and is closed once at drop.
unsafe impl Send for ControllerOwner {}
unsafe impl Sync for ControllerOwner {}
impl Drop for ControllerOwner {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "controller peer ownership not verified",
    )
}
impl ControllerOwner {
    /// Liveness of this retained process object, never a fresh PID lookup.
    pub fn is_alive(&self) -> bool {
        self.live_pid().is_ok()
    }
    pub(crate) fn duplicate(process: HANDLE) -> io::Result<Self> {
        let mut duplicate = null_mut();
        let current = unsafe { GetCurrentProcess() };
        if unsafe {
            DuplicateHandle(
                current,
                process,
                current,
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(duplicate))
    }
    fn live_pid(&self) -> io::Result<u32> {
        // Waiting on the retained object distinguishes running from an exited
        // process whose exit code happens to equal STILL_ACTIVE (259).
        let state = unsafe { WaitForSingleObject(self.0, 0) };
        if state == WAIT_FAILED {
            return Err(io::Error::last_os_error());
        }
        if state != WAIT_TIMEOUT {
            return Err(denied());
        }
        let pid = unsafe { GetProcessId(self.0) };
        if pid == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(pid)
    }
    /// Must run on this connected socket before any capability/header bytes are
    /// written. A retained process handle alone is insufficient: prove the reverse
    /// established four-tuple, not merely a listening PID or a transient port.
    pub fn verify_connected(&self, stream: &TcpStream) -> io::Result<()> {
        let (SocketAddr::V4(client), SocketAddr::V4(server)) =
            (stream.local_addr()?, stream.peer_addr()?)
        else {
            return Err(denied());
        };
        if *client.ip() != Ipv4Addr::LOCALHOST || *server.ip() != Ipv4Addr::LOCALHOST {
            return Err(denied());
        }
        let pid = self.live_pid()?;
        let mut capacity = 65536usize;
        for _ in 0..3 {
            if capacity > 4 * 1024 * 1024 {
                return Err(denied());
            }
            let mut storage = vec![0usize; capacity.div_ceil(size_of::<usize>())];
            let allocated = storage.len() * size_of::<usize>();
            let mut bytes = allocated as u32;
            let result = unsafe {
                GetExtendedTcpTable(
                    storage.as_mut_ptr().cast(),
                    &mut bytes,
                    0,
                    AF_INET as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };
            if result == ERROR_INSUFFICIENT_BUFFER {
                capacity = bytes as usize;
                continue;
            }
            if result != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(result as i32));
            }
            if bytes as usize > allocated {
                return Err(denied());
            }
            let data = unsafe {
                std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), bytes as usize)
            };
            if !matches_table(data, pid, client, server)? || self.live_pid()? != pid {
                return Err(denied());
            }
            return Ok(());
        }
        Err(denied())
    }
    /// UDP has no established peer table. This is a bounded endpoint-owner
    /// snapshot, not per-packet authentication. Use only after authenticated TCP
    /// admission, with a dedicated association port and latched sender tuple.
    /// Wildcard IPv4/IPv6 sockets can cover an actual IPv4 loopback sender;
    /// One dual-stack socket appears in both tables on Windows. Allow one row
    /// per family only when every covering row belongs to the retained child.
    /// Duplicate rows within a family and any foreign owner remain rejected.
    pub fn verify_udp_sender(&self, sender: SocketAddrV4) -> io::Result<()> {
        if *sender.ip() != Ipv4Addr::LOCALHOST || sender.port() == 0 {
            return Err(denied());
        }
        let pid = self.live_pid()?;
        let mut matches = Vec::new();
        for family in [AF_INET, AF_INET6] {
            let mut capacity = 65536usize;
            let mut complete = false;
            for _ in 0..3 {
                if capacity > 4 * 1024 * 1024 {
                    return Err(denied());
                }
                let mut storage = vec![0usize; capacity.div_ceil(size_of::<usize>())];
                let allocated = storage.len() * size_of::<usize>();
                let mut bytes = allocated as u32;
                let result = unsafe {
                    GetExtendedUdpTable(
                        storage.as_mut_ptr().cast(),
                        &mut bytes,
                        0,
                        family as u32,
                        UDP_TABLE_OWNER_PID,
                        0,
                    )
                };
                if result == ERROR_INSUFFICIENT_BUFFER {
                    capacity = bytes as usize;
                    continue;
                }
                if result != ERROR_SUCCESS {
                    return Err(io::Error::from_raw_os_error(result as i32));
                }
                if bytes as usize > allocated {
                    return Err(denied());
                }
                let data = unsafe {
                    std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), bytes as usize)
                };
                let mut family_matches = Vec::new();
                udp_owners(data, family, sender, &mut family_matches)?;
                matches.extend(family_matches);
                complete = true;
                break;
            }
            if !complete {
                return Err(denied());
            }
        }
        if matches.is_empty()
            || matches.len() > 2
            || matches.iter().any(|owner| *owner != pid)
            || self.live_pid()? != pid
        {
            return Err(denied());
        }
        Ok(())
    }
}
fn udp_owners(
    data: &[u8],
    family: u16,
    sender: SocketAddrV4,
    owners: &mut Vec<u32>,
) -> io::Result<()> {
    let (start, stride) = match family {
        AF_INET => (
            offset_of!(MIB_UDPTABLE_OWNER_PID, table),
            size_of::<MIB_UDPROW_OWNER_PID>(),
        ),
        AF_INET6 => (
            offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
            size_of::<MIB_UDP6ROW_OWNER_PID>(),
        ),
        _ => return Err(denied()),
    };
    if data.len() < start {
        return Err(denied());
    }
    let count = u32::from_ne_bytes(data[..4].try_into().map_err(|_| denied())?) as usize;
    if count > 16384
        || count
            .checked_mul(stride)
            .and_then(|len| start.checked_add(len))
            .is_none_or(|len| len > data.len())
    {
        return Err(denied());
    }
    for index in 0..count {
        let row = unsafe { data.as_ptr().add(start + index * stride) };
        let (covers, port, pid) = if family == AF_INET {
            let row = unsafe { std::ptr::read_unaligned(row.cast::<MIB_UDPROW_OWNER_PID>()) };
            (
                row.dwLocalAddr == 0 || row.dwLocalAddr == u32::from_ne_bytes(sender.ip().octets()),
                row.dwLocalPort,
                row.dwOwningPid,
            )
        } else {
            let row = unsafe { std::ptr::read_unaligned(row.cast::<MIB_UDP6ROW_OWNER_PID>()) };
            let mapped = sender.ip().to_ipv6_mapped().octets();
            (
                row.dwLocalScopeId == 0
                    && (row.ucLocalAddr == [0; 16] || row.ucLocalAddr == mapped),
                row.dwLocalPort,
                row.dwOwningPid,
            )
        };
        if covers && port >> 16 == 0 && u16::from_be(port as u16) == sender.port() {
            owners.push(pid);
        }
        if owners.len() > 1 {
            return Err(denied());
        }
    }
    Ok(())
}
fn matches_table(
    data: &[u8],
    pid: u32,
    client: SocketAddrV4,
    server: SocketAddrV4,
) -> io::Result<bool> {
    let start = offset_of!(MIB_TCPTABLE_OWNER_PID, table);
    if data.len() < start {
        return Err(denied());
    }
    let count = u32::from_ne_bytes(data[..4].try_into().map_err(|_| denied())?) as usize;
    if count > 16384
        || count
            .checked_mul(size_of::<MIB_TCPROW_OWNER_PID>())
            .and_then(|len| start.checked_add(len))
            .is_none_or(|len| len > data.len())
    {
        return Err(denied());
    }
    let mut matches = 0;
    for index in 0..count {
        let row = unsafe {
            std::ptr::read_unaligned(
                data.as_ptr()
                    .add(start + index * size_of::<MIB_TCPROW_OWNER_PID>())
                    .cast::<MIB_TCPROW_OWNER_PID>(),
            )
        };
        if row.dwState == MIB_TCP_STATE_ESTAB as u32
            && row.dwOwningPid == pid
            && row.dwLocalAddr == u32::from_ne_bytes(server.ip().octets())
            && row.dwRemoteAddr == u32::from_ne_bytes(client.ip().octets())
            && u16::from_be(row.dwLocalPort as u16) == server.port()
            && u16::from_be(row.dwRemotePort as u16) == client.port()
        {
            matches += 1;
        }
    }
    Ok(matches == 1)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::TcpListener,
        time::{Duration, Instant},
    };
    #[test]
    fn udp_table_matches_only_covering_sender_and_rejects_ambiguous_or_truncated_rows() {
        let sender = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 51000);
        let start = offset_of!(MIB_UDPTABLE_OWNER_PID, table);
        let mut bytes = vec![0u8; start + size_of::<MIB_UDPROW_OWNER_PID>()];
        bytes[..4].copy_from_slice(&1u32.to_ne_bytes());
        let mut row = MIB_UDPROW_OWNER_PID {
            dwLocalAddr: 0,
            dwLocalPort: u16::to_be(sender.port()) as u32,
            dwOwningPid: 42,
        };
        for address in [0, u32::from_ne_bytes([127, 0, 0, 1])] {
            row.dwLocalAddr = address;
            unsafe {
                std::ptr::write_unaligned(bytes.as_mut_ptr().add(start).cast(), row);
            }
            let mut owners = Vec::new();
            udp_owners(&bytes, AF_INET, sender, &mut owners).unwrap();
            assert_eq!(owners, vec![42]);
        }
        row.dwLocalAddr = u32::from_ne_bytes([192, 0, 2, 1]);
        unsafe {
            std::ptr::write_unaligned(bytes.as_mut_ptr().add(start).cast(), row);
        }
        let mut owners = Vec::new();
        udp_owners(&bytes, AF_INET, sender, &mut owners).unwrap();
        assert!(owners.is_empty());
        for len in 0..bytes.len() {
            assert!(udp_owners(&bytes[..len], AF_INET, sender, &mut Vec::new()).is_err());
        }
        row.dwLocalAddr = 0;
        unsafe {
            std::ptr::write_unaligned(bytes.as_mut_ptr().add(start).cast(), row);
        }
        let mut owners = vec![42];
        assert!(udp_owners(&bytes, AF_INET, sender, &mut owners).is_err());
        let start = offset_of!(MIB_UDP6TABLE_OWNER_PID, table);
        let mut bytes = vec![0u8; start + size_of::<MIB_UDP6ROW_OWNER_PID>()];
        bytes[..4].copy_from_slice(&1u32.to_ne_bytes());
        for address in [[0u8; 16], Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets()] {
            let row = MIB_UDP6ROW_OWNER_PID {
                ucLocalAddr: address,
                dwLocalScopeId: 0,
                dwLocalPort: u16::to_be(sender.port()) as u32,
                dwOwningPid: 42,
            };
            unsafe {
                std::ptr::write_unaligned(bytes.as_mut_ptr().add(start).cast(), row);
            }
            let mut owners = Vec::new();
            udp_owners(&bytes, AF_INET6, sender, &mut owners).unwrap();
            assert_eq!(owners, vec![42]);
        }
    }
    #[test]
    fn native_udp_endpoint_owner_requires_the_retained_process() {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let SocketAddr::V4(sender) = socket.local_addr().unwrap() else {
            panic!("fixture family");
        };
        let current = ControllerOwner::duplicate(unsafe { GetCurrentProcess() }).unwrap();
        current.verify_udp_sender(sender).unwrap();
        drop(socket);
        assert!(current.verify_udp_sender(sender).is_err());
        assert!(current
            .verify_udp_sender(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, sender.port()))
            .is_err());
    }
    #[cfg(windows)]
    #[test]
    fn native_dual_stack_udp_sender_keeps_one_retained_owner_across_both_tables() {
        use std::os::windows::io::FromRawSocket;
        use windows_sys::Win32::Networking::WinSock::*;
        struct Wsa;
        impl Drop for Wsa {
            fn drop(&mut self) {
                unsafe {
                    WSACleanup();
                }
            }
        }
        let mut data: WSADATA = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { WSAStartup(0x0202, &mut data) }, 0);
        let _wsa = Wsa;
        let raw = unsafe { socket(AF_INET6 as i32, SOCK_DGRAM, IPPROTO_UDP) };
        assert_ne!(raw, INVALID_SOCKET);
        let socket = unsafe { std::net::UdpSocket::from_raw_socket(raw as _) };
        let no = 0i32;
        assert_eq!(
            unsafe {
                setsockopt(
                    raw,
                    IPPROTO_IPV6,
                    IPV6_V6ONLY,
                    (&no as *const i32).cast(),
                    4,
                )
            },
            0
        );
        let mut address: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
        address.sin6_family = AF_INET6;
        assert_eq!(
            unsafe {
                bind(
                    raw,
                    (&address as *const SOCKADDR_IN6).cast(),
                    size_of::<SOCKADDR_IN6>() as i32,
                )
            },
            0
        );
        let receiver = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let destination = std::net::SocketAddrV6::new(
            Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
            receiver.local_addr().unwrap().port(),
            0,
            0,
        );
        socket.send_to(b"dual-stack-fixture", destination).unwrap();
        let (_, peer) = receiver.recv_from(&mut [0; 64]).unwrap();
        let SocketAddr::V4(sender) = peer else {
            panic!("fixture receive family");
        };
        let owner = ControllerOwner::duplicate(unsafe { GetCurrentProcess() }).unwrap();
        owner.verify_udp_sender(sender).unwrap();
        drop(socket);
        assert!(owner.verify_udp_sender(sender).is_err());
    }
    #[test]
    fn table_requires_exact_established_reverse_tuple_and_owner() {
        let client = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 51000);
        let server = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 52000);
        let row = MIB_TCPROW_OWNER_PID {
            dwState: 5,
            dwLocalAddr: u32::from_ne_bytes([127, 0, 0, 1]),
            dwLocalPort: u16::to_be(52000) as u32,
            dwRemoteAddr: u32::from_ne_bytes([127, 0, 0, 1]),
            dwRemotePort: u16::to_be(51000) as u32,
            dwOwningPid: 42,
        };
        let mut bytes = vec![
            0u8;
            offset_of!(MIB_TCPTABLE_OWNER_PID, table)
                + size_of::<MIB_TCPROW_OWNER_PID>()
        ];
        bytes[..4].copy_from_slice(&1u32.to_ne_bytes());
        unsafe {
            std::ptr::write_unaligned(
                bytes
                    .as_mut_ptr()
                    .add(offset_of!(MIB_TCPTABLE_OWNER_PID, table))
                    .cast(),
                row,
            );
        }
        assert!(matches_table(&bytes, 42, client, server).unwrap());
        assert!(!matches_table(&bytes, 41, client, server).unwrap());
        assert!(!matches_table(&bytes, 42, server, client).unwrap());
        for length in 0..bytes.len() {
            assert!(matches_table(&bytes[..length], 42, client, server).is_err());
        }
        bytes[..4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(matches_table(&bytes, 42, client, server).is_err());
    }
    #[test]
    #[ignore = "child-only local controller ownership fixture"]
    fn fixture_controller_peer() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        std::fs::write(
            "controller-port.txt",
            listener.local_addr().unwrap().port().to_string(),
        )
        .unwrap();
        let (_stream, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_secs(60));
    }
    #[test]
    fn actual_connected_peer_matches_owned_process_not_unrelated_pid_or_dead_handle() {
        struct Temp(std::path::PathBuf);
        impl Drop for Temp {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let temp = Temp(std::env::temp_dir().join(format!(
            "adapter-peer-proof-{}",
            super::super::windows::boot_id().unwrap()
        )));
        std::fs::create_dir(&temp.0).unwrap();
        let process = super::super::windows_process::OwnedProcess::spawn(
            &std::env::current_exe().unwrap(),
            &[
                "--exact".into(),
                "windows_controller_owner::tests::fixture_controller_peer".into(),
                "--ignored".into(),
            ],
            &temp.0,
        )
        .unwrap();
        let owner = process.controller_owner().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let port = loop {
            if let Ok(value) = std::fs::read_to_string(temp.0.join("controller-port.txt")) {
                if let Ok(port) = value.parse::<u16>() {
                    break port;
                }
            }
            assert!(Instant::now() < deadline, "fixture startup timeout");
            std::thread::sleep(Duration::from_millis(10));
        };
        let stream = TcpStream::connect_timeout(
            &SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
            Duration::from_secs(1),
        )
        .unwrap();
        owner.verify_connected(&stream).unwrap();
        let unrelated = ControllerOwner::duplicate(unsafe { GetCurrentProcess() }).unwrap();
        assert!(unrelated.verify_connected(&stream).is_err());
        process.terminate(Duration::from_secs(2)).unwrap();
        assert!(owner.verify_connected(&stream).is_err());
    }
}
