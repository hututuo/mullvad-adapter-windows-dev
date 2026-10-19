//! Isolated diagnostic UDP bridge using the official pinned MASQUE client.
//! No WG identity, TUN, routes, system proxy, key logging, or permissive verifier.
use mullvad_masque_proxy::client::{Client, ClientConfig, Error as ProxyError};
use serde::Deserialize;
use std::{
    io::{self, Read},
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{net::UdpSocket, time::timeout};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    source: Ipv4Addr,
    interface_index: u32,
    quic_ip: Ipv4Addr,
    domain: String,
    token: String,
    local_port: u16,
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && (b == 168 || b == 0))
        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113))
}
fn validate(x: &Input) -> Result<(), &'static str> {
    if !public_v4(x.quic_ip)
        || x.source.is_unspecified()
        || x.source.is_loopback()
        || x.source.is_multicast()
        || x.source.is_link_local()
        || x.interface_index == 0
        || x.domain.is_empty()
        || x.domain.len() > 253
        || !x.domain.is_ascii()
        || x.domain.split('.').any(|s| {
            s.is_empty()
                || s.len() > 63
                || s.starts_with('-')
                || s.ends_with('-')
                || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        || x.token.is_empty()
        || x.token.len() > 4096
        || !x.token.is_ascii()
        || x.token.bytes().any(|b| b <= 32 || b >= 127)
        || (x.local_port != 0 && x.local_port < 1024)
    {
        return Err("input_invalid");
    }
    Ok(())
}
#[cfg(windows)]
fn bind_outer(x: &Input) -> Result<std::net::UdpSocket, &'static str> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::*;
    let socket = std::net::UdpSocket::bind((x.source, 0)).map_err(|_| "outer_bind_failed")?;
    let index = x.interface_index.to_be();
    let raw = socket.as_raw_socket() as SOCKET;
    let rc = unsafe {
        setsockopt(
            raw,
            IPPROTO_IP,
            IP_UNICAST_IF,
            (&index as *const u32).cast(),
            4,
        )
    };
    if rc != 0 {
        return Err("outer_interface_failed");
    }
    let mut readback = 0u32;
    let mut len = 4i32;
    let rc = unsafe {
        getsockopt(
            raw,
            IPPROTO_IP,
            IP_UNICAST_IF,
            (&mut readback as *mut u32).cast(),
            &mut len,
        )
    };
    if rc != 0
        || len != 4
        || readback != x.interface_index
        || socket
            .local_addr()
            .map_err(|_| "outer_binding_readback_failed")?
            .ip()
            != x.source
    {
        return Err("outer_binding_readback_failed");
    }
    socket
        .set_nonblocking(true)
        .map_err(|_| "outer_nonblocking_failed")?;
    Ok(socket)
}
#[cfg(not(windows))]
fn bind_outer(_: &Input) -> Result<std::net::UdpSocket, &'static str> {
    Err("windows_only")
}

fn strict_tls() -> Result<Arc<rustls::ClientConfig>, &'static str> {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| "tls_config_failed")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    // Deliberately override upstream default_tls_config, whose verifier accepts all certificates.
    Ok(Arc::new(config))
}
fn error_code(e: ProxyError) -> &'static str {
    match e {
        ProxyError::Connection(quinn::ConnectionError::TransportError(e)) => {
            // QUIC CRYPTO_ERROR encodes the TLS alert; never export server text.
            let code = u64::from(e.code);
            match code {
                0x12a..=0x12e | 0x130 => "quic_certificate_alert",
                0x100..=0x1ff => "quic_tls_alert",
                _ => "quic_transport_error",
            }
        }
        ProxyError::Connection(quinn::ConnectionError::TimedOut) => "quic_idle_timeout",
        ProxyError::Connection(_) => "quic_connection_failed",
        ProxyError::UnexpectedStatus(_) => "quic_http_status_rejected",
        ProxyError::Connect(_) | ProxyError::Endpoint(_) => "quic_endpoint_failed",
        _ => "quic_proxy_failed",
    }
}
async fn run() -> Result<(), &'static str> {
    let mut raw = Vec::new();
    io::stdin()
        .take(8193)
        .read_to_end(&mut raw)
        .map_err(|_| "input_unavailable")?;
    if raw.len() > 8192 {
        return Err("input_cap");
    }
    let x: Input = serde_json::from_slice(&raw).map_err(|_| "input_invalid")?;
    raw.fill(0);
    validate(&x)?;
    let outer = UdpSocket::from_std(bind_outer(&x)?).map_err(|_| "outer_runtime_failed")?;
    let local = UdpSocket::bind((Ipv4Addr::LOCALHOST, x.local_port))
        .await
        .map_err(|_| "local_bind_failed")?;
    let local_port = local
        .local_addr()
        .map_err(|_| "local_binding_failed")?
        .port();
    let cfg = ClientConfig::builder()
        .client_socket(local)
        .quinn_socket(outer)
        .server_addr(SocketAddr::from((x.quic_ip, 443)))
        .server_host(x.domain)
        .target_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 51820)))
        .mtu(1280)
        .tls_config(strict_tls()?)
        .auth_header(Some(format!("Bearer {}", x.token)))
        .build();
    let client = timeout(Duration::from_secs(15), Client::connect(cfg))
        .await
        .map_err(|_| "quic_connect_deadline")?
        .map_err(error_code)?;
    println!("{{\"kind\":\"bridge_ready\",\"local_port\":{local_port},\"tls\":\"strict_webpki\"}}");
    timeout(Duration::from_secs(90), client.run().until_closed())
        .await
        .map_err(|_| "bridge_lifetime_expired")?
        .map_err(error_code)
}
#[tokio::main]
async fn main() {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("{{\"kind\":\"bridge_failed\",\"error\":\"internal_panic\"}}")
    }));
    if let Err(code) = run().await {
        eprintln!("{{\"kind\":\"bridge_failed\",\"error\":\"{code}\"}}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn input_rejects_private_endpoints_and_header_injection() {
        let mut x = Input {
            source: Ipv4Addr::new(192, 168, 1, 2),
            interface_index: 1,
            quic_ip: Ipv4Addr::new(23, 144, 160, 97),
            domain: "example.com".into(),
            token: "fixture".into(),
            local_port: 17943,
        };
        assert_eq!(validate(&x), Ok(()));
        x.token = "fixture\r\nInjected:yes".into();
        assert!(validate(&x).is_err());
        x.token = "fixture".into();
        x.quic_ip = Ipv4Addr::LOCALHOST;
        assert!(validate(&x).is_err());
    }
    #[test]
    fn tls_uses_authenticating_verifier_without_key_logging() {
        assert_eq!(strict_tls().unwrap().alpn_protocols, vec![b"h3".to_vec()]);
        assert!(!strict_tls().unwrap().key_log.will_log("CLIENT_RANDOM"));
    }
}
