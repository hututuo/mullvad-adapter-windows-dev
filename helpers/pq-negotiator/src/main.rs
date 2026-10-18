use std::{
    error::Error,
    io::{self, Read},
    net::{Ipv4Addr, SocketAddr},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use hyper_util::rt::tokio::TokioIo;
use serde::{Deserialize, Serialize};
use talpid_tunnel_config_client::{request_ephemeral_peer_with, RelayConfigService};
use talpid_types::net::wireguard::{PrivateKey, PublicKey};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tonic::transport::Endpoint;
use tower::service_fn;

// Mullvad's current tunnel gateway address; the config RPC is TCP/1337 inside
// the established tunnel. The caller supplies only its local SOCKS listener.
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 64, 0, 1);
const CONFIG_PORT: u16 = 1337;

#[derive(Deserialize)]
struct Input {
    // Registered parent WireGuard public key. Never pass a private key.
    parentkey: String,
    socks_ports: Vec<u16>,
    // Used only for the second hop of the same isolated negotiation.
    ephemeral_private_key: Option<String>,
}

#[derive(Serialize)]
struct Output {
    ephemeral_private_key: String,
    ephemeral_public_key: String,
    preshared_keys: Vec<String>,
    schema: u32,
}

#[tokio::main]
async fn main() {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!(r#"{{"component":"mullvad-pq-negotiator","version":"0.1.0","schema":1,"upstream_sha":"19fb87407f4b81fe15372c2c7f8a20e7ab4eb220"}}"#);
        return;
    }
    match tokio::time::timeout(std::time::Duration::from_secs(25), run()).await {
        Ok(Ok(())) => {},
        _ => { eprintln!("pq_negotiation_failed"); std::process::exit(1); }
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let mut input_json = String::new();
    io::stdin().take(4097).read_to_string(&mut input_json)?;
    if input_json.len() > 4096 { return Err("input too large".into()); }
    let input: Input = serde_json::from_str(&input_json)?;

    if input.socks_ports.is_empty() || input.socks_ports.len() > 2 || input.socks_ports.contains(&0) { return Err("invalid ports".into()); }
    let parent_public = PublicKey::from_base64(&input.parentkey)?;
    let ephemeral_private = match input.ephemeral_private_key {
        Some(encoded) => PrivateKey::from_base64(&encoded)?,
        None => PrivateKey::new_from_random(),
    };
    let ephemeral_public = ephemeral_private.public_key();

    let config_addr = SocketAddr::new(GATEWAY.into(), CONFIG_PORT);
    let mut preshared_keys = Vec::new();
    for socks_port in input.socks_ports {
    let endpoint = Endpoint::from_static("tcp://0.0.0.0:0");
    let channel = endpoint
        .connect_with_connector(service_fn(move |_| async move {
            let stream = socks5_connect(socks_port, config_addr).await?;
            Ok::<_, io::Error>(TokioIo::new(stream))
        }))
        .await?;

    // PQ-only: true enables Mullvad's ML-KEM + HQC exchange; false keeps this
    // helper from requesting DAITA settings that this standalone helper cannot
    // apply to the WireGuard data plane.
    let peer = request_ephemeral_peer_with(
        RelayConfigService::new(channel),
        parent_public.clone(),
        ephemeral_public.clone(),
        true,
        false,
    )
    .await?;
    let psk = peer
        .psk
        .ok_or_else(|| io::Error::other("PQ request returned no preshared key"))?;

    preshared_keys.push(STANDARD.encode(psk.as_bytes()));
    }

    // Its stdout contains a short-lived private key and PSK for its caller.
    let output = Output {
        ephemeral_private_key: ephemeral_private.to_base64(),
        ephemeral_public_key: ephemeral_public.to_base64(),
        preshared_keys,
        schema: 1,
    };
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

async fn socks5_connect(port: u16, target: SocketAddr) -> io::Result<TcpStream> {
    let proxy_addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect(proxy_addr).await?;

    // SOCKS5, no authentication.
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0_u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [0x05, 0x00] {
        return Err(io::Error::other("SOCKS5 proxy rejected no-auth method"));
    }

    let SocketAddr::V4(target) = target else {
        return Err(io::Error::other("config gateway must be IPv4"));
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;

    let mut reply = [0_u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(io::Error::other(format!(
            "SOCKS5 CONNECT failed (version {}, status {})",
            reply[0], reply[1]
        )));
    }

    match reply[3] {
        0x01 => {
            let mut bound_ipv4 = [0_u8; 4];
            stream.read_exact(&mut bound_ipv4).await?;
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            let mut bound_domain = vec![0_u8; usize::from(len[0])];
            stream.read_exact(&mut bound_domain).await?;
        }
        0x04 => {
            let mut bound_ipv6 = [0_u8; 16];
            stream.read_exact(&mut bound_ipv6).await?;
        }
        atyp => {
            return Err(io::Error::other(format!(
                "SOCKS5 returned unsupported address type {atyp}"
            )));
        }
    }
    let mut bound_port = [0_u8; 2];
    stream.read_exact(&mut bound_port).await?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn socks_connector_sends_literal_gateway_and_accepts_ipv4_reply() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 10];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [5, 1, 0, 1, 10, 64, 0, 1, 5, 57]);
            stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await.unwrap();
        });
        socks5_connect(port, SocketAddr::new(GATEWAY.into(), CONFIG_PORT)).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rejected_socks_method_is_not_treated_as_a_connected_tunnel() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[5, 255]).await.unwrap();
        });
        assert!(socks5_connect(port, SocketAddr::new(GATEWAY.into(), CONFIG_PORT)).await.is_err());
        server.await.unwrap();
    }
}
