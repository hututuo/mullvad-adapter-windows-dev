use mullvad_masque_proxy::client::{Client, ClientConfig};
use mullvad_quic_carrier::{
    Counters, Request, UPSTREAM_SHA, bound_remote, bridge, loopback, read_line,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::UdpSocket,
};

fn connect_error(error: mullvad_masque_proxy::client::Error) -> &'static str {
    use mullvad_masque_proxy::client::Error::*;
    match error {
        Bind(_)
        | Endpoint(_)
        | Connect(_)
        | InvalidMtu { .. }
        | InvalidMaxUdpPayload(_)
        | Uri(_)
        | ReadCerts(_)
        | ParseCerts
        | InvalidIdleTimeout(_)
        | PacketTooLarge(_) => "quic_local_init_failed",
        ClientRead(_) | ClientWrite(_) | IO(_) => "quic_local_io_failed",
        _ => "quic_connect_failed",
    }
}

async fn emit(value: Value) -> Result<(), &'static str> {
    let mut out = tokio::io::stdout();
    let mut line = serde_json::to_vec(&value).map_err(|_| "output_failed")?;
    line.push(b'\n');
    out.write_all(&line).await.map_err(|_| "parent_closed")?;
    out.flush().await.map_err(|_| "parent_closed")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Control {
    action: String,
}

async fn run() -> Result<(), &'static str> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--version-json"] {
        return emit(json!({"schema":1,"name":"mullvad-quic-carrier","version":env!("CARGO_PKG_VERSION"),"upstream_sha":UPSTREAM_SHA})).await;
    }
    if !args.is_empty() {
        return Err("invalid_arguments");
    }
    let mut input = BufReader::new(tokio::io::stdin());
    let raw = read_line(&mut input)
        .await
        .map_err(|_| "invalid_request")?
        .ok_or("missing_request")?;
    let request: Request = serde_json::from_slice(&raw).map_err(|_| "invalid_request")?;
    request.validate()?;
    let (remote, binding) = bound_remote(&request).map_err(|_| "physical_bind_failed")?;
    let local = loopback(request.remote_endpoint.is_ipv4());
    let ingress = UdpSocket::bind(local)
        .await
        .map_err(|_| "local_bind_failed")?;
    let local_endpoint = ingress.local_addr().map_err(|_| "local_bind_failed")?;
    let internal = UdpSocket::bind(local)
        .await
        .map_err(|_| "local_bind_failed")?;
    let internal_endpoint = internal.local_addr().map_err(|_| "local_bind_failed")?;
    let forward = UdpSocket::bind(local)
        .await
        .map_err(|_| "local_bind_failed")?;
    forward
        .connect(internal_endpoint)
        .await
        .map_err(|_| "local_bind_failed")?;
    let config = ClientConfig::builder()
        .client_socket(internal)
        .quinn_socket(remote)
        .server_addr(request.remote_endpoint)
        .server_host(request.server_hostname)
        .target_addr(request.target_endpoint)
        .auth_header(Some(format!("Bearer {}", request.auth_token)))
        .mtu(request.mtu)
        .build();
    let connect = tokio::time::timeout(Duration::from_secs(12), Client::connect(config));
    let client = tokio::select! {
        result=connect => result.map_err(|_|"quic_connect_timeout")?.map_err(connect_error)?,
        _=read_line(&mut input) => return Err("parent_stopped_before_ready"),
    };
    let counters = Arc::new(Counters::default());
    let mut relay = tokio::spawn(bridge(ingress, forward, Arc::clone(&counters)));
    let mut closed = Box::pin(client.run().until_closed());
    if let Err(error) = emit(
        json!({"schema":1,"event":"ready","transport":"quic","local_endpoint":local_endpoint,
        "carrier_authenticated":true,"upstream_sha":UPSTREAM_SHA,"binding":binding}),
    )
    .await
    {
        relay.abort();
        return Err(error);
    }
    let outcome = loop {
        tokio::select! {
            line=read_line(&mut input) => {
                let line=match line {Ok(Some(v))=>v,Ok(None)=>break Ok(()),Err(_)=>break Err("invalid_control")};
                let control:Control=match serde_json::from_slice(&line) {Ok(v)=>v,Err(_)=>break Err("invalid_control")};
                match control.action.as_str() {
                    "stop"=>break Ok(()),
                    "stats"=>if let Err(error)=emit(counters.snapshot()).await {break Err(error);},
                    _=>break Err("invalid_control"),
                }
            }
            _=&mut closed => break Err("carrier_closed"),
            _=&mut relay => break Err("local_bridge_failed"),
        }
    };
    relay.abort();
    drop(closed);
    outcome
}

#[tokio::main]
async fn main() {
    std::panic::set_hook(Box::new(|_| eprintln!("carrier_internal_error")));
    if let Err(code) = run().await {
        let _ = emit(json!({"schema":1,"event":"error","code":code})).await;
        std::process::exit(1);
    }
}
