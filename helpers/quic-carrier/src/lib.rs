//! One owned, physically bound official QUIC carrier. No device private keys.
use serde::{Deserialize, Serialize};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt},
    net::UdpSocket,
};

pub const UPSTREAM_SHA: &str = "19fb87407f4b81fe15372c2c7f8a20e7ab4eb220";
pub const MAX_LINE: usize = 16_384;

// Deliberately no Debug: the directory's CONNECT token must not enter logs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: u32,
    pub remote_endpoint: SocketAddr,
    pub server_hostname: String,
    pub auth_token: String,
    pub target_endpoint: SocketAddr,
    pub interface_index: u32,
    pub interface_name: String,
    pub source_address: Option<IpAddr>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}
fn default_mtu() -> u16 {
    1280
}

impl Request {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != 1
            || self.remote_endpoint.port() != 443
            || self.remote_endpoint.ip().is_unspecified()
            || self.remote_endpoint.ip().is_multicast()
            || self.target_endpoint != SocketAddr::from((Ipv4Addr::LOCALHOST, 51820))
            || self.interface_index == 0
            || self.interface_name.is_empty()
            || self.interface_name.len() > 256
            || self.interface_name.chars().any(char::is_control)
            || !(1280..=1500).contains(&self.mtu)
        {
            return Err("invalid_request");
        }
        if self.server_hostname.len() > 253
            || self.server_hostname.is_empty()
            || !self.server_hostname.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            })
            || self.auth_token.is_empty()
            || self.auth_token.len() > 4096
            || self.auth_token.starts_with("Bearer")
            || !self.auth_token.bytes().all(|c| (33..=126).contains(&c))
        {
            return Err("invalid_request");
        }
        if self.source_address.is_some_and(|ip| {
            ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_ipv4() != self.remote_endpoint.is_ipv4()
        }) {
            return Err("invalid_binding");
        }
        #[cfg(windows)]
        if self.source_address.is_none() {
            return Err("invalid_binding");
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub struct Binding {
    pub interface_index: u32,
    pub interface_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_address: Option<IpAddr>,
    pub remote_endpoint: SocketAddr,
}

pub fn loopback(ipv4: bool) -> SocketAddr {
    if ipv4 {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
    } else {
        SocketAddr::from((Ipv6Addr::LOCALHOST, 0))
    }
}

pub fn bound_remote(request: &Request) -> io::Result<(UdpSocket, Binding)> {
    request
        .validate()
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let source = request
        .source_address
        .unwrap_or(if request.remote_endpoint.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        });
    let socket = std::net::UdpSocket::bind(SocketAddr::new(source, 0))?;
    bind_interface(&socket, request)?;
    socket.set_nonblocking(true)?;
    Ok((
        UdpSocket::from_std(socket)?,
        Binding {
            interface_index: request.interface_index,
            interface_name: request.interface_name.clone(),
            source_address: request.source_address,
            remote_endpoint: request.remote_endpoint,
        },
    ))
}

#[cfg(unix)]
fn bind_interface(socket: &std::net::UdpSocket, request: &Request) -> io::Result<()> {
    use std::{ffi::CString, os::fd::AsRawFd};
    let name = CString::new(request.interface_name.as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let actual = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if actual == 0 || actual != request.interface_index {
        return Err(io::Error::from(io::ErrorKind::AddrNotAvailable));
    }
    let fd = socket.as_raw_fd();
    #[cfg(target_os = "macos")]
    {
        let (level, option) = if request.remote_endpoint.is_ipv4() {
            (libc::IPPROTO_IP, libc::IP_BOUND_IF)
        } else {
            (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
        };
        let index = request.interface_index;
        if unsafe { libc::setsockopt(fd, level, option, (&index as *const u32).cast(), 4) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut readback = 0u32;
        let mut len = 4;
        if unsafe {
            libc::getsockopt(
                fd,
                level,
                option,
                (&mut readback as *mut u32).cast(),
                &mut len,
            )
        } != 0
            || len != 4
            || readback != index
        {
            return Err(io::Error::from(io::ErrorKind::AddrNotAvailable));
        }
    }
    #[cfg(target_os = "linux")]
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.as_bytes_with_nul().len() as _,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return Err(io::Error::from(io::ErrorKind::Unsupported));
    Ok(())
}

#[cfg(windows)]
fn bind_interface(socket: &std::net::UdpSocket, request: &Request) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET, SOCKET_ERROR,
        WSAGetLastError, getsockopt, setsockopt,
    };
    let (level, option, index) = if request.remote_endpoint.is_ipv4() {
        (IPPROTO_IP, IP_UNICAST_IF, request.interface_index.to_be())
    } else {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, request.interface_index)
    };
    let fd = socket.as_raw_socket() as SOCKET;
    if unsafe { setsockopt(fd, level, option, (&index as *const u32).cast(), 4) } == SOCKET_ERROR {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    let mut actual = 0u32;
    let mut length = 4;
    if unsafe {
        getsockopt(
            fd,
            level,
            option,
            (&mut actual as *mut u32).cast(),
            &mut length,
        )
    } == SOCKET_ERROR
        || length != 4
        || actual != index
    {
        return Err(io::Error::from(io::ErrorKind::AddrNotAvailable));
    }
    Ok(())
}

/// Bound input before allocating a JSON string, including a missing newline.
pub async fn read_line<R: AsyncBufRead + Unpin>(input: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut result = Vec::new();
    loop {
        let buf = input.fill_buf().await?;
        if buf.is_empty() {
            return if result.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::from(io::ErrorKind::UnexpectedEof))
            };
        }
        let take = buf
            .iter()
            .position(|b| *b == b'\n')
            .map_or(buf.len(), |i| i + 1);
        if result.len() + take > MAX_LINE {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        result.extend_from_slice(&buf[..take]);
        let ended = result.last() == Some(&b'\n');
        input.consume(take);
        if ended {
            return Ok(Some(result));
        }
    }
}

#[derive(Default)]
pub struct Counters {
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    wg_initiations: AtomicU64,
    wg_response_packets: AtomicU64,
    wg_cookie_packets: AtomicU64,
}
impl Counters {
    pub fn snapshot(&self) -> serde_json::Value {
        let get = |v: &AtomicU64| v.load(Ordering::Relaxed);
        serde_json::json!({"schema":1,"event":"stats", "tx_packets":get(&self.tx_packets),
            "rx_packets":get(&self.rx_packets),"tx_bytes":get(&self.tx_bytes),"rx_bytes":get(&self.rx_bytes),
            "wg_initiations":get(&self.wg_initiations),"wg_response_packets":get(&self.wg_response_packets),
            "wg_cookie_packets":get(&self.wg_cookie_packets)})
    }
    fn packet(&self, data: &[u8], rx: bool) {
        let inc = |v: &AtomicU64, n| {
            v.fetch_add(n, Ordering::Relaxed);
        };
        if rx {
            inc(&self.rx_packets, 1);
            inc(&self.rx_bytes, data.len() as u64);
        } else {
            inc(&self.tx_packets, 1);
            inc(&self.tx_bytes, data.len() as u64);
        }
        // Visible type headers are observations, never authenticated WG proof.
        if data.len() >= 4 {
            match (&data[..4], rx, data.len()) {
                ([1, 0, 0, 0], false, 148) => inc(&self.wg_initiations, 1),
                ([2, 0, 0, 0], true, 92) => inc(&self.wg_response_packets, 1),
                ([3, 0, 0, 0], true, 64) => inc(&self.wg_cookie_packets, 1),
                _ => {}
            }
        }
    }
}

/// One local sender; the only remote traffic is owned by the QUIC client.
pub async fn bridge(
    ingress: UdpSocket,
    forward: UdpSocket,
    counters: Arc<Counters>,
) -> io::Result<()> {
    let mut client = None;
    let mut outbound = vec![0u8; 65_535];
    let mut inbound = vec![0u8; 65_535];
    loop {
        tokio::select! {
            received = ingress.recv_from(&mut outbound) => {
                let (len, from) = received?;
                if !from.ip().is_loopback() || client.is_some_and(|v| v != from) { continue; }
                client = Some(from);
                forward.send(&outbound[..len]).await?;
                counters.packet(&outbound[..len], false);
            }
            received = forward.recv(&mut inbound) => {
                let len = received?;
                if let Some(client) = client {
                    ingress.send_to(&inbound[..len], client).await?;
                    counters.packet(&inbound[..len], true);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        serde_json::from_value(serde_json::json!({"schema":1,"remote_endpoint":"192.0.2.9:443",
            "server_hostname":"example.invalid","auth_token":"fixture-token","target_endpoint":"127.0.0.1:51820",
            "interface_index":1,"interface_name":"lo0","source_address":"127.0.0.1","mtu":1280})).unwrap()
    }
    #[test]
    fn rejects_bad_contract_and_binding_without_disclosing_token() {
        let mut r = request();
        assert!(r.validate().is_ok());
        r.target_endpoint = "192.0.2.9:51820".parse().unwrap();
        assert!(r.validate().is_err());
        r = request();
        r.auth_token = "Bearer fixture".into();
        assert!(r.validate().is_err());
        r = request();
        r.interface_index = 0;
        assert!(r.validate().is_err());
        r = request();
        r.source_address = Some("::1".parse().unwrap());
        assert!(r.validate().is_err());
        r = request();
        r.server_hostname = "host\nsecret".into();
        assert!(r.validate().is_err());
    }
    #[tokio::test]
    async fn input_is_bounded_before_json_and_requires_delimiter() {
        let mut input = &b"{}\n{\"action\":\"stop\"}\n"[..];
        assert_eq!(read_line(&mut input).await.unwrap().unwrap(), b"{}\n");
        assert!(read_line(&mut input).await.unwrap().is_some());
        assert!(read_line(&mut input).await.unwrap().is_none());
        let huge = vec![b'x'; MAX_LINE + 1];
        let mut input = &huge[..];
        assert!(read_line(&mut input).await.is_err());
        let mut input = &b"unfinished"[..];
        assert!(read_line(&mut input).await.is_err());
    }
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn mac_binding_is_read_back_and_name_index_mismatch_fails_closed() {
        let name = std::ffi::CString::new("lo0").unwrap();
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        assert_ne!(index, 0);
        let mut r = request();
        r.interface_index = index;
        let (socket, receipt) = bound_remote(&r).unwrap();
        assert_eq!(receipt.interface_index, index);
        assert_eq!(
            socket.local_addr().unwrap().ip(),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
        r.interface_index = index + 10000;
        assert!(bound_remote(&r).is_err());
    }
    #[tokio::test]
    async fn bridge_reports_datagrams_and_does_not_claim_authentication() {
        let ingress = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let inlet = ingress.local_addr().unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forward = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        forward.connect(server.local_addr().unwrap()).await.unwrap();
        let counters = Arc::new(Counters::default());
        let task = tokio::spawn(bridge(ingress, forward, Arc::clone(&counters)));
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut init = vec![0u8; 148];
        init[0] = 1;
        peer.send_to(&init, inlet).await.unwrap();
        let mut buf = [0u8; 256];
        let (n, from) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            server.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(n, 148);
        let mut response = vec![0u8; 92];
        response[0] = 2;
        server.send_to(&response, from).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), peer.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let stats = counters.snapshot();
        assert_eq!(stats["wg_initiations"], 1);
        assert_eq!(stats["wg_response_packets"], 1);
        assert!(stats.get("authenticated").is_none());
        task.abort();
    }
}
